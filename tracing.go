package main

import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaLog "github.com/Motmedel/utils_go/pkg/schema/log"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	connectTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/connect"
	destroyConnectionTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/destroy_connection"
	execveTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/execve"
	freePacketTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/free_packet"
	tcpRetransmissionTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/tcp_retransmission"
	tcpSetStateTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/tcp_set_state"
	"golang.org/x/sync/errgroup"
)

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: schemaLog.ReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", "tracing"))),
	}
	slog.SetDefault(logger.Logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errGroup, errGroupCtx := errgroup.WithContext(ctx)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when removing the memory lock.",
			fmt.Errorf("rlimit remove mem lock: %w", err),
		)
	}

	var objs tracing_service.BpfObjects
	if err := tracing_service.LoadBpfObjects(&objs, nil); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when loading objects.",
			fmt.Errorf("load bpf objects: %w", err),
			objs,
		)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			logger.Warning(
				"An error occurred when closing the objects.",
				motmedelErrors.NewWithTrace(fmt.Errorf("close bpf objects: %w", err), objs),
			)
		}
	}()

	iterators := []iter.Seq2[*schema.Base, error]{
		destroyConnectionTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.NfCtHelperDestroy,
			objs.BpfMaps.DestroyConnectionEvents,
		),
		tcpRetransmissionTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.TcpRetransmitSkb,
			objs.BpfMaps.TcpRetransmissionEvents,
		),
		tcpSetStateTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.TraceInetSockSetState,
			objs.BpfMaps.TcpSetStateEvents,
		),
		connectTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.TcpConnect,
			objs.BpfMaps.ConnectEvents,
		),
		//openTracing.Run(
		//	errGroupCtx,
		//	objs.BpfPrograms.TraceOpenat,
		//	objs.BpfMaps.FileOpenEvents,
		//),
		freePacketTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.TraceKfreeSkb,
			objs.BpfMaps.PacketDropEvents,
			objs.BpfMaps.PacketDropReasonFilter,
		),
		execveTracing.Run(
			errGroupCtx,
			objs.BpfPrograms.EnterExecve,
			objs.BpfMaps.ExecveEvents,
		),
	}

	var printMutex sync.Mutex
iteratorsLoop:
	for _, iterator := range iterators {
		select {
		case <-errGroupCtx.Done():
			break iteratorsLoop
		default:
			errGroup.Go(
				func() error {
					for base, err := range iterator {
						if err != nil {
							return fmt.Errorf("iterator: %w", err)
						}
						if base == nil {
							continue
						}

						data, err := json.Marshal(base)
						if err != nil {
							logger.Error(
								"An error occurred when marshaling a base. Skipping.",
								motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), base),
							)
							continue
						}

						printMutex.Lock()
						fmt.Println(string(data))
						printMutex.Unlock()
					}

					return nil
				},
			)
		}
	}

	if err := errGroup.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.FatalWithExitingMessage(
			"An error occurred when running a tracer.",
			fmt.Errorf("errgroup wait: %w", err),
		)
	}
}
