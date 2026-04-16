package tcp_icmp_error

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
)

// icmpV4UnreachCodes / icmpV6UnreachCodes map ICMP destination-unreachable
// codes to short human-readable strings. Populated for the common cases that
// affect TCP connectivity; unknown codes fall through to numeric rendering.
var icmpV4UnreachCodes = map[uint8]string{
	0:  "net_unreachable",
	1:  "host_unreachable",
	2:  "protocol_unreachable",
	3:  "port_unreachable",
	4:  "frag_needed",
	5:  "source_route_failed",
	6:  "net_unknown",
	7:  "host_unknown",
	9:  "net_prohibited",
	10: "host_prohibited",
	13: "comm_prohibited",
}

var icmpV6UnreachCodes = map[uint8]string{
	0: "no_route",
	1: "admin_prohibited",
	3: "address_unreachable",
	4: "port_unreachable",
}

// icmpV4Types maps the handful of ICMPv4 types that matter here.
var icmpV4Types = map[uint8]string{
	3:  "destination_unreachable",
	11: "time_exceeded",
	12: "parameter_problem",
}

// icmpV6Types maps the handful of ICMPv6 types that matter here.
var icmpV6Types = map[uint8]string{
	1: "destination_unreachable",
	2: "packet_too_big",
	3: "time_exceeded",
	4: "parameter_problem",
}

// classify returns (typeName, codeName, errnoCode) for an ICMP error. errnoCode
// mirrors the sk_err the kernel will set for this ICMP.
func classify(family uint16, icmpType uint8, icmpCode uint8) (string, string, string) {
	var typeName, codeName, errnoCode string
	switch family {
	case uint16(syscall.AF_INET):
		typeName = icmpV4Types[icmpType]
		if icmpType == 3 {
			codeName = icmpV4UnreachCodes[icmpCode]
			switch icmpCode {
			case 0:
				errnoCode = "ENETUNREACH"
			case 1, 5, 6, 7, 11, 12:
				errnoCode = "EHOSTUNREACH"
			case 2, 3:
				errnoCode = "ECONNREFUSED"
			case 4:
				errnoCode = "EMSGSIZE"
			case 9, 10, 13:
				errnoCode = "EHOSTUNREACH"
			}
		}
	case uint16(syscall.AF_INET6):
		typeName = icmpV6Types[icmpType]
		if icmpType == 1 {
			codeName = icmpV6UnreachCodes[icmpCode]
			switch icmpCode {
			case 0:
				errnoCode = "ENETUNREACH"
			case 1, 3:
				errnoCode = "EHOSTUNREACH"
			case 4:
				errnoCode = "ECONNREFUSED"
			}
		} else if icmpType == 2 {
			errnoCode = "EMSGSIZE"
		}
	}
	if typeName == "" {
		typeName = strconv.Itoa(int(icmpType))
	}
	return typeName, codeName, errnoCode
}

func EnrichWithTcpIcmpErrorEvent(base *schema.Base, event *tracing_service.BpfTcpIcmpErrorEvent) error {
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

	typeName, codeName, errnoCode := classify(event.AddressFamily, event.IcmpType, event.IcmpCode)

	if base.Event == nil {
		base.Event = &schema.Event{}
	}
	base.Event.Outcome = "failure"
	if errnoCode != "" {
		base.Event.Code = errnoCode
	}

	var srcAddr, dstAddr string
	if s := base.Source; s != nil {
		srcAddr = net.JoinHostPort(s.Ip, strconv.Itoa(s.Port))
	}
	if d := base.Destination; d != nil {
		dstAddr = net.JoinHostPort(d.Ip, strconv.Itoa(d.Port))
	}
	codeLabel := codeName
	if codeLabel == "" {
		codeLabel = strconv.Itoa(int(event.IcmpCode))
	}
	base.Message = fmt.Sprintf("%s -> %s tcp icmp_error %s/%s", srcAddr, dstAddr, typeName, codeLabel)

	return nil
}

// Run attaches both the IPv4 and IPv6 ICMP error fentry programs and reads
// events from the shared ringbuf until ctx is cancelled.
func Run(
	ctx context.Context,
	programV4 *ebpf.Program,
	programV6 *ebpf.Program,
	ebpfMap *ebpf.Map,
) iter.Seq2[*tracing_service.EventResult, error] {
	return func(yield func(*tracing_service.EventResult, error) bool) {
		if programV4 == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("programV4")))
			return
		}

		if programV6 == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("programV6")))
			return
		}

		if ebpfMap == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("ebpf map")))
			return
		}

		linkV4, err := link.AttachTracing(link.TracingOptions{Program: programV4})
		if err != nil {
			yield(nil, motmedelErrors.NewWithTrace(fmt.Errorf("link attach tracing (v4): %w", err)))
			return
		}
		defer func() {
			if err := linkV4.Close(); err != nil {
				slog.WarnContext(
					motmedelContext.WithError(
						ctx,
						motmedelErrors.NewWithTrace(fmt.Errorf("tracing link close (v4): %w", err)),
					),
					"An error occurred when closing a tracing link.",
				)
			}
		}()

		linkV6, err := link.AttachTracing(link.TracingOptions{Program: programV6})
		if err != nil {
			yield(nil, motmedelErrors.NewWithTrace(fmt.Errorf("link attach tracing (v6): %w", err)))
			return
		}
		defer func() {
			if err := linkV6.Close(); err != nil {
				slog.WarnContext(
					motmedelContext.WithError(
						ctx,
						motmedelErrors.NewWithTrace(fmt.Errorf("tracing link close (v6): %w", err)),
					),
					"An error occurred when closing a tracing link.",
				)
			}
		}()

		var mu sync.Mutex
		receiverCtx, cancelReceiver := context.WithCancel(ctx)
		defer cancelReceiver()

		err = tracing.RunMapReceiver(
			receiverCtx,
			ebpfMap,
			func(event *tracing_service.BpfTcpIcmpErrorEvent) {
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
						Type:     []string{"connection", "error"},
						Action:   "tcp_icmp_error",
						Module:   "tracing",
						Reason:   "An ICMP error was delivered to a TCP socket.",
						Dataset:  "tracing.tcp_icmp_error",
					},
				}

				EnrichWithTcpIcmpErrorEvent(base, event)

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
			yield(nil, fmt.Errorf("run map receiver: %w", err))
		}
	}
}
