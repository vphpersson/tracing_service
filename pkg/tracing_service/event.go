package tracing_service

import (
	"log/slog"

	"github.com/Motmedel/utils_go/pkg/schema"
)

type EventResult struct {
	Base  *schema.Base
	Attrs []slog.Attr
}

func BaseToSlogAttrs(base *schema.Base) []slog.Attr {
	if base == nil {
		return nil
	}

	var attrs []slog.Attr

	if base.Event != nil {
		attrs = append(attrs, slog.Any("event", base.Event))
	}
	if base.Source != nil {
		attrs = append(attrs, slog.Any("source", base.Source))
	}
	if base.Destination != nil {
		attrs = append(attrs, slog.Any("destination", base.Destination))
	}
	if base.Network != nil {
		attrs = append(attrs, slog.Any("network", base.Network))
	}
	if base.Process != nil {
		attrs = append(attrs, slog.Any("process", base.Process))
	}
	if base.File != nil {
		attrs = append(attrs, slog.Any("file", base.File))
	}
	if base.Tcp != nil {
		attrs = append(attrs, slog.Any("tcp", base.Tcp))
	}
	if base.User != nil {
		attrs = append(attrs, slog.Any("user", base.User))
	}
	if base.Related != nil {
		attrs = append(attrs, slog.Any("related", base.Related))
	}
	if len(base.Labels) > 0 {
		attrs = append(attrs, slog.Any("labels", base.Labels))
	}
	if len(base.Tags) > 0 {
		attrs = append(attrs, slog.Any("tags", base.Tags))
	}

	return attrs
}
