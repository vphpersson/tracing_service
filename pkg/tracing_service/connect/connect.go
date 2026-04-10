package connect

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/cilium/ebpf"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
)

func EnrichWithConnectEvent(base *schema.Base, event *tracing_service.BpfConnectEvent) error {
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

	tracing.EnrichWithConnectionInformationTransport(
		base,
		event.SourceAddress,
		event.SourcePort,
		event.DestinationAddress,
		event.DestinationPort,
		event.AddressFamily,
		event.TransportProtocol,
	)

	tracing.EnrichWithSourceUser(base, event.UserId)

	tracing.EnrichWithProcessInformation(
		base,
		event.ProcessId,
		event.ProcessTitle,
		event.ParentProcessId,
		event.UserId,
		event.GroupId,
	)

	ecsProcess := base.Process
	if ecsProcess == nil {
		ecsProcess = &schema.Process{}
		base.Process = ecsProcess
	}

	executableName := string(bytes.TrimRight(event.ExecutableName[:], "\x00"))
	if executableName != "" {
		ecsProcess.Name = executableName
	}

	cmdlineRaw := bytes.TrimRight(event.CommandLine[:], "\x00")
	if len(cmdlineRaw) > 0 {
		commandLine := string(bytes.ReplaceAll(cmdlineRaw, []byte{0}, []byte{' '}))
		ecsProcess.CommandLine = commandLine

		if ecsProcess.Executable == "" {
			if idx := bytes.IndexByte(cmdlineRaw, 0); idx > 0 {
				ecsProcess.Executable = string(cmdlineRaw[:idx])
			} else {
				ecsProcess.Executable = string(cmdlineRaw)
			}
			ecsProcess.Name = filepath.Base(ecsProcess.Executable)
		}
	}

	ecsProcessParent := ecsProcess.Parent
	if ecsProcessParent == nil {
		ecsProcessParent = &schema.Process{}
		ecsProcess.Parent = ecsProcessParent
	}

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

	if event.AddressFamily == uint16(syscall.AF_INET6) {
		if tracing_service.IsIPv4MappedIPv6(event.SourceAddress) || tracing_service.IsIPv4MappedIPv6(event.DestinationAddress) {
			if base.Network == nil {
				base.Network = &schema.Network{}
			}
			base.Network.Type = "ipv4"
		}
	}

	if communityId := schemaUtils.CommunityIdFromTargets(base.Source, base.Destination, int(event.TransportProtocol)); communityId != "" {
		if base.Network == nil {
			base.Network = &schema.Network{}
		}
		base.Network.CommunityId = append(base.Network.CommunityId, communityId)
	}

	var srcAddr, dstAddr, transport string
	if s := base.Source; s != nil {
		srcAddr = net.JoinHostPort(s.Ip, strconv.Itoa(s.Port))
	}
	if d := base.Destination; d != nil {
		dstAddr = net.JoinHostPort(d.Ip, strconv.Itoa(d.Port))
	}
	if n := base.Network; n != nil {
		transport = n.Transport
	}
	executable := ""
	if p := base.Process; p != nil {
		executable = p.Executable
	}
	base.Message = fmt.Sprintf("%s -> %s %s connect %s", srcAddr, dstAddr, transport, executable)

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

		err := tracing.RunTracingMapReceiver(
			receiverCtx,
			program,
			ebpfMap,
			func(event *tracing_service.BpfConnectEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Reason:  "A connect call was made.",
						Dataset: "tracing.connect",
					},
				}

				EnrichWithConnectEvent(base, event)

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
