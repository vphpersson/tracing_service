package free_packet

import (
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/vphpersson/tracing/pkg/tracing"
	"github.com/vphpersson/tracing_service/pkg/tracing_service"
	"iter"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// errorReasonNames is the allowlist of skb_drop_reason values we want to
// surface as events. The intent is to capture genuine error conditions —
// protocol corruption, resource exhaustion, routing/neighbor failures,
// firewall drops, authentication failures — and exclude routine drops
// (RST teardown, duplicate/out-of-order segments, PAWS, promiscuous-mode
// noise, intentional BPF/socket-filter drops, etc.).
var errorReasonNames = map[string]struct{}{
	// Header / checksum corruption
	"SKB_DROP_REASON_PKT_TOO_SMALL":    {},
	"SKB_DROP_REASON_PKT_TOO_BIG":      {},
	"SKB_DROP_REASON_HDR_TRUNC":        {},
	"SKB_DROP_REASON_DEV_HDR":          {},
	"SKB_DROP_REASON_INVALID_PROTO":    {},
	"SKB_DROP_REASON_IP_INHDR":         {},
	"SKB_DROP_REASON_IP_CSUM":          {},
	"SKB_DROP_REASON_TCP_CSUM":         {},
	"SKB_DROP_REASON_UDP_CSUM":         {},
	"SKB_DROP_REASON_ICMP_CSUM":        {},
	"SKB_DROP_REASON_SKB_CSUM":         {},
	"SKB_DROP_REASON_IPV6_BAD_EXTHDR":  {},
	"SKB_DROP_REASON_IP_NOPROTO":       {},
	"SKB_DROP_REASON_UNHANDLED_PROTO":  {},
	"SKB_DROP_REASON_DUP_FRAG":         {},
	"SKB_DROP_REASON_FRAG_REASM_TIMEOUT": {},
	"SKB_DROP_REASON_FRAG_TOO_FAR":     {},

	// Routing / neighbor failures
	"SKB_DROP_REASON_IP_OUTNOROUTES":   {},
	"SKB_DROP_REASON_IP_INNOROUTES":    {},
	"SKB_DROP_REASON_IP_INADDRERRORS":  {},
	"SKB_DROP_REASON_IP_INVALID_SOURCE": {},
	"SKB_DROP_REASON_IP_INVALID_DEST":  {},
	"SKB_DROP_REASON_IP_LOCAL_SOURCE":  {},
	"SKB_DROP_REASON_NEIGH_FAILED":     {},
	"SKB_DROP_REASON_NEIGH_DEAD":       {},
	"SKB_DROP_REASON_NEIGH_CREATEFAIL": {},
	"SKB_DROP_REASON_NEIGH_QUEUEFULL":  {},

	// Firewall / policy
	"SKB_DROP_REASON_NETFILTER_DROP":   {},
	"SKB_DROP_REASON_IP_RPFILTER":      {},
	"SKB_DROP_REASON_XFRM_POLICY":      {},
	"SKB_DROP_REASON_BPF_CGROUP_EGRESS": {},
	"SKB_DROP_REASON_TCP_MINTTL":       {},

	// Resource exhaustion / congestion
	"SKB_DROP_REASON_NOMEM":            {},
	"SKB_DROP_REASON_PROTO_MEM":        {},
	"SKB_DROP_REASON_SOCKET_RCVBUFF":   {},
	"SKB_DROP_REASON_SOCKET_BACKLOG":   {},
	"SKB_DROP_REASON_CPU_BACKLOG":      {},
	"SKB_DROP_REASON_FULL_RING":        {},
	"SKB_DROP_REASON_QDISC_DROP":       {},
	"SKB_DROP_REASON_QDISC_OVERLIMIT":  {},
	"SKB_DROP_REASON_QDISC_CONGESTED":  {},
	"SKB_DROP_REASON_TCP_OFO_DROP":     {},
	"SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE": {},

	// TCP protocol violations / authentication failures
	"SKB_DROP_REASON_TCP_FLAGS":               {},
	"SKB_DROP_REASON_TCP_INVALID_SYN":         {},
	"SKB_DROP_REASON_TCP_INVALID_SEQUENCE":    {},
	"SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE": {},
	"SKB_DROP_REASON_TCP_AUTH_HDR":            {},
	"SKB_DROP_REASON_TCP_MD5NOTFOUND":         {},
	"SKB_DROP_REASON_TCP_MD5UNEXPECTED":       {},
	"SKB_DROP_REASON_TCP_MD5FAILURE":          {},
	"SKB_DROP_REASON_TCP_AONOTFOUND":          {},
	"SKB_DROP_REASON_TCP_AOUNEXPECTED":        {},
	"SKB_DROP_REASON_TCP_AOKEYNOTFOUND":       {},
	"SKB_DROP_REASON_TCP_AOFAILURE":           {},
	"SKB_DROP_REASON_TCP_ZEROWINDOW":          {},

	// Tunneling
	"SKB_DROP_REASON_VXLAN_INVALID_HDR":  {},
	"SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND": {},
}

// loadReasonInfo loads the kernel's skb_drop_reason enum from BTF and returns
// both a value→name lookup table (for message formatting) and a slice of
// values to install in the BPF allowlist filter. The numeric values of
// skb_drop_reason are not stable across kernel versions, so resolving them
// at runtime via BTF is the only correct option.
func loadReasonInfo() (map[uint16]string, []uint16, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("btf load kernel spec: %w", err)
	}

	var enum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &enum); err != nil {
		return nil, nil, fmt.Errorf("btf type by name skb_drop_reason: %w", err)
	}

	names := make(map[uint16]string, len(enum.Values))
	var allowed []uint16
	for _, v := range enum.Values {
		value := uint16(v.Value)
		names[value] = strings.TrimPrefix(v.Name, "SKB_DROP_REASON_")
		if _, ok := errorReasonNames[v.Name]; ok {
			allowed = append(allowed, value)
		}
	}
	return names, allowed, nil
}

func populateReasonFilter(filterMap *ebpf.Map, allowed []uint16) error {
	for _, reason := range allowed {
		var dummy uint8 = 1
		if err := filterMap.Put(reason, dummy); err != nil {
			return fmt.Errorf("filter map put %d: %w", reason, err)
		}
	}
	return nil
}

func EnrichWithPacketFreedEvent(
	base *schema.Base,
	event *tracing_service.BpfPacketDropEvent,
	reasonNames map[uint16]string,
) error {
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

	var reasonPart string
	if reasonString, ok := reasonNames[event.Reason]; ok {
		reasonPart = reasonString
	} else {
		reasonPart = fmt.Sprintf("%d", event.Reason)
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

	base.Message = fmt.Sprintf("%s -> %s %s free_packet %s", srcAddr, dstAddr, transport, reasonPart)

	return nil
}

func Run(
	ctx context.Context,
	program *ebpf.Program,
	ebpfMap *ebpf.Map,
	reasonFilterMap *ebpf.Map,
) iter.Seq2[*schema.Base, error] {
	return func(yield func(*schema.Base, error) bool) {
		if program == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("program")))
			return
		}

		if ebpfMap == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("ebpf map")))
			return
		}

		if reasonFilterMap == nil {
			yield(nil, motmedelErrors.NewWithTrace(nil_error.New("ebpf map")))
			return
		}

		reasonNames, allowedReasons, err := loadReasonInfo()
		if err != nil {
			yield(nil, fmt.Errorf("load reason info: %w", err))
			return
		}

		if err := populateReasonFilter(reasonFilterMap, allowedReasons); err != nil {
			yield(nil, fmt.Errorf("populate reason filter: %w", err))
			return
		}

		var mu sync.Mutex
		receiverCtx, cancelReceiver := context.WithCancel(ctx)
		defer cancelReceiver()

		err = tracing.RunTracepointMapReceiver(
			receiverCtx,
			program,
			"skb",
			"kfree_skb",
			ebpfMap,
			func(event *tracing_service.BpfPacketDropEvent) {
				if receiverCtx.Err() != nil {
					return
				}

				if event == nil {
					return
				}

				base := &schema.Base{
					Event: &schema.Event{
						Reason:  "A packet was freed.",
						Dataset: "tracing.kfree_skb",
					},
				}

				EnrichWithPacketFreedEvent(base, event, reasonNames)

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
