package execve

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelStrings "github.com/Motmedel/utils_go/pkg/strings"
	"github.com/cilium/ebpf"
	tracingErrors "github.com/vphpersson/tracing/pkg/errors"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"path/filepath"
)

func EnrichWithExecveEvent(base *ecs.Base, event *tracing_service.BpfExecveEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	base.Timestamp = tracing.ConvertEbpfTimestampToIso8601(event.TimestampNs, tracing.GetBootTime())

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
		ecsProcess = &ecs.Process{}
		base.Process = ecsProcess
	}

	ecsProcess.Args = argvStrings
	ecsProcess.ArgsCount = len(argvStrings)
	ecsProcess.CommandLine = motmedelStrings.ShellJoin(argvStrings)
	ecsProcess.Executable = executable
	ecsProcess.Name = filepath.Base(executable)

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &ecs.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

	ecsProcessParent.Title = ecsProcess.Title

	base.Message = fmt.Sprintf("%s ran %q", ecsProcessParent.Title, ecsProcess.CommandLine)
}

func Run(ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map) iter.Seq2[*ecs.Base, error] {
	return func(yield func(*ecs.Base, error) bool) {
		if program == nil {
			yield(nil, motmedelErrors.NewWithTrace(tracingErrors.ErrNilEbpfProgram))
			return
		}

		if ebpfMap == nil {
			yield(nil, motmedelErrors.NewWithTrace(tracingErrors.ErrNilEbpfMap))
			return
		}

		err := tracing.RunTracepointMapReceiver(
			ctx,
			program,
			"syscalls",
			"sys_enter_execve",
			ebpfMap,
			func(event *tracing_service.BpfExecveEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "An execve call was made.",
						Dataset: "tracing.execve",
					},
				}

				EnrichWithExecveEvent(base, event)

				if !yield(base, nil) {
					return
				}
			},
		)

		if err != nil {
			yield(nil, fmt.Errorf("run tracing map receiver: %w", err))
		}
	}
}
