package open

import (
	"bytes"
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/cilium/ebpf"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"log/slog"
	"path/filepath"
	"sync"
)

func EnrichWithFileOpenEvent(base *schema.Base, event *tracing_service.BpfFileOpenEvent) ([]any, error) {
	if base == nil {
		return nil, nil
	}

	if event == nil {
		return nil, nil
	}

	bootTime, err := tracing.GetBootTime()
	if err != nil {
		return nil, fmt.Errorf("get boot time: %w", err)
	}

	base.Timestamp = tracing.ConvertEbpfTimestampToIso8601(event.TimestampNs, bootTime)

	tracing.EnrichWithProcessInformation(
		base,
		event.ProcessId,
		event.ProcessTitle,
		event.ParentProcessId,
		event.UserId,
		event.GroupId,
	)

	filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

	if filename != "" {
		ecsFile := base.File
		if ecsFile == nil {
			ecsFile = &schema.File{}
			base.File = ecsFile
		}

		ecsFile.Path = filename
		ecsFile.Name = filepath.Base(filename)
		ecsFile.Directory = filepath.Dir(filename)
		if ext := filepath.Ext(filename); ext != "" {
			ecsFile.Extension = ext[1:]
		}
	}

	processTitle := ""
	if ecsProcess := base.Process; ecsProcess != nil {
		processTitle = ecsProcess.Title
	}

	base.Message = fmt.Sprintf("%s opened %q", processTitle, filename)

	var tracingArgs []any
	tracingArgs = append(tracingArgs, slog.Int("flags", int(event.Flags)))
	tracingArgs = append(tracingArgs, slog.Int("mode", int(event.Mode)))

	return tracingArgs, nil
}

func Run(ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map) iter.Seq2[*tracing_service.EventResult, error] {
	return func(yield func(*tracing_service.EventResult, error) bool) {
		if program == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("program")))
			return
		}

		if ebpfMap == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("ebpf map")))
			return
		}

		var mu sync.Mutex
		receiverCtx, cancelReceiver := context.WithCancel(ctx)
		defer cancelReceiver()

		err := tracing.RunTracepointMapReceiver(
			receiverCtx,
			program,
			"syscalls",
			"sys_enter_openat",
			ebpfMap,
			func(event *tracing_service.BpfFileOpenEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Kind:     "event",
						Category: []string{"file"},
						Type:     []string{"access"},
						Action:   "openat",
						Module:   "tracing",
						Reason:   "An openat call was made.",
						Dataset:  "tracing.openat",
					},
				}

				tracingArgs, _ := EnrichWithFileOpenEvent(base, event)

				result := &tracing_service.EventResult{Base: base}
				if len(tracingArgs) > 0 {
					result.Attrs = []slog.Attr{slog.Group("tracing", tracingArgs...)}
				}

				mu.Lock()
				defer mu.Unlock()
				select {
				case <-receiverCtx.Done():
					return
				default:
					if !yield(result, nil) {
						cancelReceiver()
						return
					}
				}
			},
		)

		if err != nil {
			yield(nil, fmt.Errorf("run tracing map receiver: %w", err))
		}
	}
}
