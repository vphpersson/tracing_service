package main

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
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

	eventHandler := slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			AddSource:   false,
			Level:       slog.LevelInfo,
			ReplaceAttr: schemaLog.ReplaceAttr,
		},
	)

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

	iterators := []iter.Seq2[*tracing_service.EventResult, error]{
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
		tcpRetransmissionTracing.RunSynack(
			errGroupCtx,
			objs.BpfPrograms.TcpRetransmitSynack,
			objs.BpfMaps.TcpRetransmissionSynackEvents,
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
					for result, err := range iterator {
						if err != nil {
							return fmt.Errorf("iterator: %w", err)
						}
						if result == nil || result.Base == nil {
							continue
						}

						base := result.Base

						attrs := tracing_service.BaseToSlogAttrs(base)
						attrs = append(attrs, result.Attrs...)

						eventTime, _ := time.Parse(time.RFC3339Nano, base.Timestamp)
						record := slog.NewRecord(eventTime, slog.LevelInfo, base.Message, 0)
						record.AddAttrs(attrs...)

						printMutex.Lock()
						_ = eventHandler.Handle(context.Background(), record)
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
