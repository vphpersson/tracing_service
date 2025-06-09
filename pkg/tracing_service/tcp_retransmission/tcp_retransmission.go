package tcp_retransmission

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

func EnrichWithTcpRetransmissionEvent(base *ecs.Base, event *tracing_service.BpfTcpRetransmissionEvent) {
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

	base.Message = ecs.MakeConnectionMessage(base, "")
}

func EnrichWithTcpRetransmissionSynAckEvent(base *ecs.Base, event *tracing_service.BpfTcpRetransmissionSynackEvent) {
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

	base.Message = ecs.MakeConnectionMessage(base, "")
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
			"tcp",
			"tcp_retransmit_skb",
			ebpfMap,
			func(event *tracing_service.BpfTcpRetransmissionEvent) {
				if event == nil {
					return
				}

				base := &ecs.Base{
					Event: &ecs.Event{
						Reason:  "A TCP retransmission was performed.",
						Dataset: "tracing.tcp_retransmit_skb",
					},
				}

				EnrichWithTcpRetransmissionEvent(base, event)

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
