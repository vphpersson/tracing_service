package execve

import (
	"bytes"
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	motmedelStrings "github.com/Motmedel/utils_go/pkg/strings"
	"github.com/cilium/ebpf"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"path/filepath"
	"sync"
)

func EnrichWithExecveEvent(base *schema.Base, event *tracing_service.BpfExecveEvent) error {
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

	executable := string(bytes.TrimRight(event.Filename[:], "\x00"))

	argvStrings := []string{executable}
	for i := uint32(1); i < event.Argc && int(i) < len(event.Argv); i++ {
		argString := string(bytes.TrimRight(event.Argv[i][:], "\x00"))
		if argString != "" {
			argvStrings = append(argvStrings, argString)
		}
	}

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &schema.Process{}
		base.Process = ecsProcess
	}

	// process.title from bpf_get_current_comm is the pre-exec comm, which
	// is the parent's title, not the new process's.
	parentTitle := ecsProcess.Title
	ecsProcess.Title = ""

	ecsProcess.Args = argvStrings
	ecsProcess.ArgsCount = len(argvStrings)
	ecsProcess.CommandLine = motmedelStrings.ShellJoin(argvStrings)
	ecsProcess.Executable = executable
	ecsProcess.Name = filepath.Base(executable)

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &schema.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Title = parentTitle

	parentExeName := string(bytes.TrimRight(event.ParentExecutableName[:], "\x00"))
	if parentExeName != "" {
		ecsProcessParent.Name = parentExeName
	}

	parentCmdlineRaw := bytes.TrimRight(event.ParentCommandLine[:], "\x00")
	if len(parentCmdlineRaw) > 0 {
		parentCommandLine := string(bytes.ReplaceAll(parentCmdlineRaw, []byte{0}, []byte{' '}))
		ecsProcessParent.CommandLine = parentCommandLine

		if ecsProcessParent.Executable == "" {
			if idx := bytes.IndexByte(parentCmdlineRaw, 0); idx > 0 {
				ecsProcessParent.Executable = string(parentCmdlineRaw[:idx])
			} else {
				ecsProcessParent.Executable = string(parentCmdlineRaw)
			}
			ecsProcessParent.Name = filepath.Base(ecsProcessParent.Executable)
		}
	}

	parentExe := ecsProcessParent.Executable
	if parentExe == "" {
		parentExe = ecsProcessParent.Name
	}
	if parentExe == "" {
		parentExe = ecsProcessParent.Title
	}

	base.Message = fmt.Sprintf("execve: %s -> %s", parentExe, ecsProcess.Executable)

	return nil
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
			"sys_enter_execve",
			ebpfMap,
			func(event *tracing_service.BpfExecveEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Kind:     "event",
						Category: []string{"process"},
						Type:     []string{"start"},
						Action:   "execve",
						Module:   "tracing",
						Reason:   "An execve call was made.",
						Dataset:  "tracing.execve",
					},
				}

				EnrichWithExecveEvent(base, event)

				mu.Lock()
				defer mu.Unlock()
				select {
				case <-receiverCtx.Done():
					return
				default:
					if !yield(&tracing_service.EventResult{Base: base}, nil) {
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
