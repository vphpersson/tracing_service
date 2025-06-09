package free_packet

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
)

var ReasonToString = map[uint16]string{
	1:   "CONSUMED",
	2:   "NOT_SPECIFIED",
	3:   "NO_SOCKET",
	4:   "SOCKET_CLOSE",
	5:   "SOCKET_FILTER",
	6:   "SOCKET_RCVBUFF",
	7:   "UNIX_DISCONNECT",
	8:   "UNIX_SKIP_OOB",
	9:   "PKT_TOO_SMALL",
	10:  "TCP_CSUM",
	11:  "UDP_CSUM",
	12:  "NETFILTER_DROP",
	13:  "OTHERHOST",
	14:  "IP_CSUM",
	15:  "IP_INHDR",
	16:  "IP_RPFILTER",
	17:  "UNICAST_IN_L2_MULTICAST",
	18:  "XFRM_POLICY",
	19:  "IP_NOPROTO",
	20:  "PROTO_MEM",
	21:  "TCP_AUTH_HDR",
	22:  "TCP_MD5NOTFOUND",
	23:  "TCP_MD5UNEXPECTED",
	24:  "TCP_MD5FAILURE",
	25:  "TCP_AONOTFOUND",
	26:  "TCP_AOUNEXPECTED",
	27:  "TCP_AOKEYNOTFOUND",
	28:  "TCP_AOFAILURE",
	29:  "SOCKET_BACKLOG",
	30:  "TCP_FLAGS",
	31:  "TCP_ABORT_ON_DATA",
	32:  "TCP_ZEROWINDOW",
	33:  "TCP_OLD_DATA",
	34:  "TCP_OVERWINDOW",
	35:  "TCP_OFOMERGE",
	36:  "TCP_RFC7323_PAWS",
	37:  "TCP_RFC7323_PAWS_ACK",
	38:  "TCP_OLD_SEQUENCE",
	39:  "TCP_INVALID_SEQUENCE",
	40:  "TCP_INVALID_ACK_SEQUENCE",
	41:  "TCP_RESET",
	42:  "TCP_INVALID_SYN",
	43:  "TCP_CLOSE",
	44:  "TCP_FASTOPEN",
	45:  "TCP_OLD_ACK",
	46:  "TCP_TOO_OLD_ACK",
	47:  "TCP_ACK_UNSENT_DATA",
	48:  "TCP_OFO_QUEUE_PRUNE",
	49:  "TCP_OFO_DROP",
	50:  "IP_OUTNOROUTES",
	51:  "BPF_CGROUP_EGRESS",
	52:  "IPV6DISABLED",
	53:  "NEIGH_CREATEFAIL",
	54:  "NEIGH_FAILED",
	55:  "NEIGH_QUEUEFULL",
	56:  "NEIGH_DEAD",
	57:  "TC_EGRESS",
	58:  "SECURITY_HOOK",
	59:  "QDISC_DROP",
	60:  "QDISC_OVERLIMIT",
	61:  "QDISC_CONGESTED",
	62:  "CAKE_FLOOD",
	63:  "FQ_BAND_LIMIT",
	64:  "FQ_HORIZON_LIMIT",
	65:  "FQ_FLOW_LIMIT",
	66:  "CPU_BACKLOG",
	67:  "XDP",
	68:  "TC_INGRESS",
	69:  "UNHANDLED_PROTO",
	70:  "SKB_CSUM",
	71:  "SKB_GSO_SEG",
	72:  "SKB_UCOPY_FAULT",
	73:  "DEV_HDR",
	74:  "DEV_READY",
	75:  "FULL_RING",
	76:  "NOMEM",
	77:  "HDR_TRUNC",
	78:  "TAP_FILTER",
	79:  "TAP_TXFILTER",
	80:  "ICMP_CSUM",
	81:  "INVALID_PROTO",
	82:  "IP_INADDRERRORS",
	83:  "IP_INNOROUTES",
	84:  "IP_LOCAL_SOURCE",
	85:  "IP_INVALID_SOURCE",
	86:  "IP_LOCALNET",
	87:  "IP_INVALID_DEST",
	88:  "PKT_TOO_BIG",
	89:  "DUP_FRAG",
	90:  "FRAG_REASM_TIMEOUT",
	91:  "FRAG_TOO_FAR",
	92:  "TCP_MINTTL",
	93:  "IPV6_BAD_EXTHDR",
	94:  "IPV6_NDISC_FRAG",
	95:  "IPV6_NDISC_HOP_LIMIT",
	96:  "IPV6_NDISC_BAD_CODE",
	97:  "IPV6_NDISC_BAD_OPTIONS",
	98:  "IPV6_NDISC_NS_OTHERHOST",
	99:  "QUEUE_PURGE",
	100: "TC_COOKIE_ERROR",
	101: "PACKET_SOCK_ERROR",
	102: "TC_CHAIN_NOTFOUND",
	103: "TC_RECLASSIFY_LOOP",
	104: "VXLAN_INVALID_HDR",
	105: "VXLAN_VNI_NOT_FOUND",
	106: "MAC_INVALID_SOURCE",
	107: "VXLAN_ENTRY_EXISTS",
	108: "NO_TX_TARGET",
	109: "IP_TUNNEL_ECN",
	110: "TUNNEL_TXINFO",
	111: "LOCAL_MAC",
	112: "ARP_PVLAN_DISABLE",
	113: "MAC_IEEE_MAC_CONTROL",
	114: "BRIDGE_INGRESS_STP_STATE",
}

func EnrichWithPacketFreedEvent(base *ecs.Base, event *tracing_service.BpfPacketDropEvent) {
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
		event.TransportProtocol,
	)

	var reasonPart string
	if reasonString, ok := ReasonToString[event.Reason]; ok {
		reasonPart = fmt.Sprintf("%s ", reasonString)
	}

	base.Message = ecs.MakeConnectionMessage(base, fmt.Sprintf("%s(%d)", reasonPart, event.Reason))
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
			"skb",
			"kfree_skb",
			ebpfMap,
			func(event *tracing_service.BpfPacketDropEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A packet was freed.",
						Dataset: "tracing.kfree_skb",
					},
				}

				EnrichWithPacketFreedEvent(base, event)

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
