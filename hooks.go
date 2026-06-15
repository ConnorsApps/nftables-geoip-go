package geoip

import (
	"context"
	"time"
)

// SpanHook starts a unit of work named name and returns a function to invoke when it
// ends (with its resulting error). The returned context is threaded into the work so
// the hook may attach a child span (e.g. an OpenTelemetry span). It lets callers wire
// in tracing without this library depending on any tracing package. When nil, span
// boundaries are not reported.
type SpanHook func(ctx context.Context, name string) (context.Context, func(error))

// MetricsHook is invoked once per Sync with the elapsed duration and result (nil error
// on success). It lets callers record metrics without this library depending on any
// metrics package. When nil, no metrics are reported.
type MetricsHook func(ctx context.Context, d time.Duration, err error)

// span invokes the configured SpanHook if set, otherwise returns the context unchanged
// and a no-op end function.
func (s *Syncer) span(ctx context.Context, name string) (context.Context, func(error)) {
	if s.startSpan == nil {
		return ctx, func(error) {}
	}
	return s.startSpan(ctx, name)
}
