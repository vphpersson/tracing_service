package tcp_retransmission

import (
	"context"
	"fmt"
	"iter"
	"net"
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

func EnrichWithTcpRetransmissionEvent(base *schema.Base, event *tracing_service.BpfTcpRetransmissionEvent) error {
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
		6,
	)

	var stateSuffix string
	if stateName, ok := tcpStateNames[event.State]; ok {
		stateSuffix = stateName
		ecsTcp := base.Tcp
		if ecsTcp == nil {
			ecsTcp = &schema.Tcp{}
			base.Tcp = ecsTcp
		}
		ecsTcp.State = stateName
	}

	if event.AddressFamily == uint16(syscall.AF_INET6) {
		if tracing_service.IsIPv4MappedIPv6(event.SourceAddress) || tracing_service.IsIPv4MappedIPv6(event.DestinationAddress) {
			if base.Network == nil {
				base.Network = &schema.Network{}
			}
			base.Network.Type = "ipv4"
		}
	}

	if communityId := schemaUtils.CommunityIdFromTargets(base.Source, base.Destination, 6); communityId != "" {
		if base.Network == nil {
			base.Network = &schema.Network{}
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

	base.Message = fmt.Sprintf("%s -> %s tcp tcp_retransmission %s", srcAddr, dstAddr, stateSuffix)

	return nil
}

func EnrichWithTcpRetransmissionSynAckEvent(base *schema.Base, event *tracing_service.BpfTcpRetransmissionSynackEvent) error {
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
		6,
	)

	if event.AddressFamily == uint16(syscall.AF_INET6) {
		if tracing_service.IsIPv4MappedIPv6(event.SourceAddress) || tracing_service.IsIPv4MappedIPv6(event.DestinationAddress) {
			if base.Network == nil {
				base.Network = &schema.Network{}
			}
			base.Network.Type = "ipv4"
		}
	}

	if communityId := schemaUtils.CommunityIdFromTargets(base.Source, base.Destination, 6); communityId != "" {
		if base.Network == nil {
			base.Network = &schema.Network{}
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

	base.Message = fmt.Sprintf("%s -> %s tcp tcp_retransmission_synack", srcAddr, dstAddr)

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
			"tcp",
			"tcp_retransmit_skb",
			ebpfMap,
			func(event *tracing_service.BpfTcpRetransmissionEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Kind:     "event",
						Category: []string{"network"},
						Type:     []string{"connection", "info"},
						Action:   "tcp_retransmit_skb",
						Module:   "tracing",
						Reason:   "A TCP retransmission was performed.",
						Dataset:  "tracing.tcp_retransmit_skb",
					},
				}

				EnrichWithTcpRetransmissionEvent(base, event)

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

func RunSynack(ctx context.Context, program *ebpf.Program, ebpfMap *ebpf.Map) iter.Seq2[*tracing_service.EventResult, error] {
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
			"tcp",
			"tcp_retransmit_synack",
			ebpfMap,
			func(event *tracing_service.BpfTcpRetransmissionSynackEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Kind:     "event",
						Category: []string{"network"},
						Type:     []string{"connection", "info"},
						Action:   "tcp_retransmit_synack",
						Module:   "tracing",
						Reason:   "A TCP SYN/ACK retransmission was performed.",
						Dataset:  "tracing.tcp_retransmit_synack",
					},
				}

				EnrichWithTcpRetransmissionSynAckEvent(base, event)

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
