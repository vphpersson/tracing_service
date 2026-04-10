package tcp_set_state

import (
	"context"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/cilium/ebpf"
	tracingErrors "github.com/vphpersson/tracing/pkg/errors"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"net"
	"strconv"
	"sync"
	"syscall"
)

var tcpStateNames = map[uint16]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

func stateName(state uint16) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return strconv.Itoa(int(state))
}

func EnrichWithTcpSetStateEvent(base *ecs.Base, event *tracing_service.BpfTcpSetStateEvent) {
	if base == nil {
		return
	}

	if event == nil {
		return
	}

	base.Timestamp = tracing.ConvertEbpfTimestampToIso8601(event.TimestampNs, tracing.GetBootTime())

	tracing.EnrichWithConnectionInformationTransport(
		base,
		event.SourceAddress,
		event.SourcePort,
		event.DestinationAddress,
		event.DestinationPort,
		event.AddressFamily,
		6,
	)

	ecsTcp := base.Tcp
	if ecsTcp == nil {
		ecsTcp = &ecs.Tcp{}
		base.Tcp = ecsTcp
	}
	ecsTcp.State = stateName(event.NewState)

	if event.AddressFamily == uint16(syscall.AF_INET6) {
		if tracing_service.IsIPv4MappedIPv6(event.SourceAddress) || tracing_service.IsIPv4MappedIPv6(event.DestinationAddress) {
			if base.Network == nil {
				base.Network = &ecs.Network{}
			}
			base.Network.Type = "ipv4"
		}
	}

	if communityId := ecs.CommunityIdFromTargets(base.Source, base.Destination, 6); communityId != "" {
		if base.Network == nil {
			base.Network = &ecs.Network{}
		}
		base.Network.CommunityId = append(base.Network.CommunityId, communityId)
	}

	var srcAddr, dstAddr string
	if s := base.Source; s != nil {
		srcAddr = net.JoinHostPort(s.Ip, strconv.Itoa(s.Port))
	}
	if d := base.Destination; d != nil {
		dstAddr = net.JoinHostPort(d.Ip, strconv.Itoa(d.Port))
	}
	base.Message = fmt.Sprintf(
		"tcp_set_state: %s -> %s %s -> %s",
		srcAddr,
		dstAddr,
		stateName(event.OldState),
		stateName(event.NewState),
	)
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

		var mu sync.Mutex
		receiverCtx, cancelReceiver := context.WithCancel(ctx)
		defer cancelReceiver()

		err := tracing.RunTracepointMapReceiver(
			receiverCtx,
			program,
			"sock",
			"inet_sock_set_state",
			ebpfMap,
			func(event *tracing_service.BpfTcpSetStateEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A TCP socket changed state.",
						Dataset: "tracing.inet_sock_set_state",
					},
				}

				EnrichWithTcpSetStateEvent(base, event)

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
			yield(nil, fmt.Errorf("run tracepoint map receiver: %w", err))
		}
	}
}
