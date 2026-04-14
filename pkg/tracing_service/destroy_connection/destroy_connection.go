package destroy_connection

import (
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/cilium/ebpf"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var tcpStateIdToName = map[uint8]string{
	0: "",
	1: "SYN_SENT",
	2: "SYN_RECV",
	3: "ESTABLISHED",
	4: "FIN_WAIT",
	5: "CLOSE_WAIT",
	6: "LAST_ACK",
	7: "TIME_WAIT",
	8: "CLOSE",
	// NOTE: The old name for this seems to be "LISTEN".
	9:  "SYN_SENT_2",
	10: "MAX",
	11: "IGNORE",
	12: "RETRANS",
	13: "UNACK",
	14: "TIMEOUT_MAX",
}

const (
	IPS_EXPECTED_BIT      = 1 << 0
	IPS_SEEN_REPLY_BIT    = 1 << 1
	IPS_ASSURED_BIT       = 1 << 2
	IPS_CONFIRMED_BIT     = 1 << 3
	IPS_SRC_NAT_BIT       = 1 << 4
	IPS_DST_NAT_BIT       = 1 << 5
	IPS_SEQ_ADJUST_BIT    = 1 << 6
	IPS_SRC_NAT_DONE_BIT  = 1 << 7
	IPS_DST_NAT_DONE_BIT  = 1 << 8
	IPS_DYING_BIT         = 1 << 9
	IPS_FIXED_TIMEOUT_BIT = 1 << 10
)

func translateStatusBits(status int) []string {
	var names []string

	if status&IPS_EXPECTED_BIT != 0 {
		names = append(names, "EXPECTED")
	}
	if status&IPS_SEEN_REPLY_BIT != 0 {
		names = append(names, "SEEN_REPLY")
	}
	if status&IPS_ASSURED_BIT != 0 {
		names = append(names, "ASSURED")
	}
	if status&IPS_CONFIRMED_BIT != 0 {
		names = append(names, "CONFIRMED")
	}
	if status&IPS_SRC_NAT_BIT != 0 {
		names = append(names, "SRC_NAT")
	}
	if status&IPS_DST_NAT_BIT != 0 {
		names = append(names, "DST_NAT")
	}
	if status&IPS_SEQ_ADJUST_BIT != 0 {
		names = append(names, "SEQ_ADJUST")
	}
	if status&IPS_SRC_NAT_DONE_BIT != 0 {
		names = append(names, "SRC_NAT_DONE")
	}
	if status&IPS_DST_NAT_DONE_BIT != 0 {
		names = append(names, "DST_NAT_DONE")
	}
	if status&IPS_DYING_BIT != 0 {
		names = append(names, "DYING")
	}
	if status&IPS_FIXED_TIMEOUT_BIT != 0 {
		names = append(names, "FIXED_TIMEOUT")
	}

	return names
}

func EnrichWithDestroyConnectionEvent(base *schema.Base, event *tracing_service.BpfDestroyConnectionEvent) ([]any, error) {
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

	tracing.EnrichWithConnectionInformationTransport(
		base,
		event.SourceAddress,
		event.SourcePort,
		event.DestinationAddress,
		event.DestinationPort,
		event.AddressFamily,
		event.TransportProtocol,
	)

	if event.Start != 0 || event.Stop != 0 {
		ecsEvent := base.Event
		if ecsEvent == nil {
			ecsEvent = &schema.Event{}
			base.Event = ecsEvent
		}

		ecsEvent.Start = time.Unix(
			int64(event.Start/1e9),
			int64(event.Start)%1e9,
		).UTC().Format("2006-01-02T15:04:05.999999999Z")

		ecsEvent.End = time.Unix(
			int64(event.Stop/1e9),
			int64(event.Stop)%1e9,
		).UTC().Format("2006-01-02T15:04:05.999999999Z")

		if event.Stop > event.Start {
			ecsEvent.Duration = int64(event.Stop - event.Start)
		}
	}

	tcpStateName, ok := tcpStateIdToName[event.TcpState]
	if event.TransportProtocol == 6 && ok {
		ecsTcp := base.Tcp
		if ecsTcp == nil {
			ecsTcp = &schema.Tcp{}
			base.Tcp = ecsTcp
		}
		ecsTcp.State = tcpStateName
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

	if event.SourceBytes != 0 || event.SourcePackets != 0 || event.DestinationBytes != 0 || event.DestinationPackets != 0 {
		if base.Source != nil {
			base.Source.Bytes = int(event.SourceBytes)
			base.Source.Packets = int(event.SourcePackets)
		}
		if base.Destination != nil {
			base.Destination.Bytes = int(event.DestinationBytes)
			base.Destination.Packets = int(event.DestinationPackets)
		}
		if base.Network == nil {
			base.Network = &schema.Network{}
		}
		base.Network.Bytes = int64(event.SourceBytes) + int64(event.DestinationBytes)
		base.Network.Packets = int64(event.SourcePackets) + int64(event.DestinationPackets)
	}

	var isError bool
	var errorMessage string
	if event.TransportProtocol == 6 {
		if event.TcpState != 8 && event.TcpState != 7 {
			isError = true
			stateName := tcpStateIdToName[event.TcpState]
			errorMessage = fmt.Sprintf("TCP connection destroyed in unexpected conntrack state: %s.", stateName)
		}
	} else if event.TransportProtocol == 17 {
		if event.ConntrackStatusMask&IPS_SEEN_REPLY_BIT == 0 {
			isError = true
			errorMessage = "UDP connection destroyed without a reply being observed."
		}
	}

	if isError {
		ecsEvent := base.Event
		if ecsEvent != nil {
			ecsEvent.Type = append(ecsEvent.Type, "error")
		}
		base.Error = &schema.Error{Message: errorMessage}
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
	var tracingArgs []any

	if event.ConntrackStatusMask != 0 {
		statusNames := translateStatusBits(int(event.ConntrackStatusMask))
		if len(statusNames) > 0 {
			tracingArgs = append(tracingArgs, slog.String("conntrack_status", strings.Join(statusNames, ",")))
		}
	}

	if event.Timeout != 0 {
		tracingArgs = append(tracingArgs, slog.Any("timeout", event.Timeout))
	}

	tracingArgs = append(tracingArgs, slog.Any("tcp_last_direction", event.TcpLastDirection))

	var stateSuffix string
	if event.TransportProtocol == 6 {
		if name, ok := tcpStateIdToName[event.TcpState]; ok {
			stateSuffix = " " + name
		}
	}
	base.Message = fmt.Sprintf("%s -> %s %s destroy_connection%s", srcAddr, dstAddr, transport, stateSuffix)

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

		err := tracing.RunTracingMapReceiver(
			receiverCtx,
			program,
			ebpfMap,
			func(event *tracing_service.BpfDestroyConnectionEvent) {
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
						Type:     []string{"connection", "end"},
						Action:   "destroy_connection",
						Module:   "tracing",
						Reason:   "A connection was destroyed by Conntrack.",
						Dataset:  "tracing.destroy_connection",
					},
				}

				tracingArgs, _ := EnrichWithDestroyConnectionEvent(base, event)

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
