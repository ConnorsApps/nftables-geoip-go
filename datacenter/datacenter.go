// Package datacenter fetches and aggregates the datacenter IP CIDR ranges published
// by cloud providers. The built-in providers cover AWS, GCP, DigitalOcean, and Azure;
// callers can supply their own by implementing Provider.
package datacenter

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// SpanHook starts a named span and returns an end function; see geoip.SpanHook.
type SpanHook = func(ctx context.Context, name string) (context.Context, func(error))

func callSpan(ctx context.Context, h SpanHook, name string) (context.Context, func(error)) {
	if h == nil {
		return ctx, func(error) {}
	}
	return h(ctx, name)
}

// providerTimeout bounds each individual provider fetch so one hung endpoint cannot
// stall the whole sync.
const providerTimeout = 30 * time.Second

// Provider fetches the IPv4 and IPv6 datacenter CIDR ranges published by a single
// cloud provider. Implement this to add a custom source.
type Provider interface {
	// Name identifies the provider in logs and error messages.
	Name() string
	// Fetch returns the provider's IPv4 and IPv6 prefixes using the given client.
	Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error)
}

// Default returns the built-in providers: AWS, GCP, DigitalOcean, and Azure.
func Default() []Provider {
	return []Provider{AWS{}, GCP{}, DigitalOcean{}, Azure{}}
}

// Fetch fetches CIDR ranges from every provider and returns the aggregated IPv4 and
// IPv6 prefix sets. Each provider is bounded by an individual timeout. Per-provider
// failures are returned (not fatal); successful providers still contribute, so the
// caller should decide whether the combined result is acceptable. hook is optional;
// when non-nil a "datacenter.<name>" span is recorded for each provider.
func Fetch(ctx context.Context, client *http.Client, providers []Provider, hook SpanHook) (v4, v6 []netip.Prefix, errs []error) {
	for _, p := range providers {
		pctx, cancel := context.WithTimeout(ctx, providerTimeout)
		pctx, end := callSpan(pctx, hook, "datacenter."+p.Name())
		pv4, pv6, err := p.Fetch(pctx, client)
		end(err)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		v4 = append(v4, pv4...)
		v6 = append(v6, pv6...)
	}

	v4 = AggregatePrefixes(v4)
	v6 = AggregatePrefixes(v6)
	return v4, v6, errs
}
