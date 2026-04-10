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
	"path/filepath"
	"sync"
)

func EnrichWithFileOpenEvent(base *schema.Base, event *tracing_service.BpfFileOpenEvent) error {
	if base == nil {
		return nil
	}

	if event == nil {
		return nil
	}

	bootTime, err := tracing.GetBootTime()
	if err != nil {
		return fmt.Errorf("get boot time: %w", err)
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

	return nil
}

func Run(ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map) iter.Seq2[*schema.Base, error] {
	return func(yield func(*schema.Base, error) bool) {
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
						Reason:  "An openat call was made.",
						Dataset: "tracing.openat",
					},
				}

				EnrichWithFileOpenEvent(base, event)

				mu.Lock()
				defer mu.Unlock()
				select {
				case <-receiverCtx.Done():
					return
				default:
					if !yield(base, nil) {
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
