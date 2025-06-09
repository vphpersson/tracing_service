package main

import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	connectTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/connect"
	destroyConnectionTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/destroy_connection"
	tcpRetransmissionTracing "github.com/vphpersson/tracing_service/pkg/tracing_service/tcp_retransmission"
	"golang.org/x/sync/errgroup"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
						ReplaceAttr: ecs.TimestampReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", "tracing"))),
	}
	slog.SetDefault(logger.Logger)

	errGroup, errGroupCtx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(errGroupCtx)
	defer cancel()

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

	objs := tracing_service.BpfObjects{}
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

	iterators := []iter.Seq2[*ecs.Base, error]{
		destroyConnectionTracing.Run(
			ctx,
			objs.BpfPrograms.NfCtHelperDestroy,
			objs.BpfMaps.DestroyConnectionEvents,
		),
		tcpRetransmissionTracing.Run(
			ctx,
			objs.BpfPrograms.TcpRetransmitSkb,
			objs.BpfMaps.TcpRetransmissionEvents,
		),
		connectTracing.Run(
			ctx,
			objs.BpfPrograms.TcpConnect,
			objs.BpfMaps.ConnectEvents,
		),
		//openTracing.Run(
		//	ctx,
		//	objs.BpfPrograms.TraceOpenat,
		//	objs.BpfMaps.FileOpenEvents,
		//),
		//freePacketTracing.Run(
		//	ctx,
		//	objs.BpfPrograms.TraceKfreeSkb,
		//	objs.BpfMaps.PacketDropEvents,
		//),
		//execveTracing.Run(
		//	ctx,
		//	objs.BpfPrograms.EnterExecve,
		//	objs.BpfMaps.ExecveEvents,
		//),
	}

	var printMutex sync.Mutex
	for _, iterator := range iterators {
		select {
		case <-ctx.Done():
			continue
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

	if err := errGroup.Wait(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when running a tracer.",
			fmt.Errorf("errgroup wait: %w", err),
		)
	}

	<-ctx.Done()
}
