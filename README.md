# nftables-geoip-go

Generate [nftables](https://nftables.org) map/set files from [MaxMind GeoLite2
Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) data plus
cloud-provider datacenter CIDRs (AWS, GCP, DigitalOcean, Azure) — to mark or filter
traffic by country of origin and to flag datacenter/cloud IPs.

Requires a free MaxMind license key ([maxmind.com](https://www.maxmind.com)), passed via
`MAXMIND_LICENSE_KEY` (CLI) or `Config.MaxMindLicenseKey` (library).

## Library usage

```go
import geoip "github.com/ConnorsApps/nftables-geoip-go"

s := geoip.New(geoip.Config{
    OutputDir:         "/etc/nftables/generated",
    TrustedCountries:  []string{"us", "de", "fr"}, // ISO alpha-2; the "interesting" maps
    MaxMindLicenseKey: os.Getenv("MAXMIND_LICENSE_KEY"),
})

s.Sync(ctx)   // one-shot: download → sanity-check → render → validate → install
go s.Run(ctx) // sync now, then every SyncInterval (default 7 days) until ctx cancelled
```

Only `OutputDir` and `MaxMindLicenseKey` are required; `New` defaults every other field.

## Configuration

| `Config` field | CLI flag / env var | Default | Purpose |
|----------------|--------------------|---------|---------|
| `OutputDir` | `-out` / `GEOIP_OUTPUT_DIR` | `.` | output directory |
| `TrustedCountries` | `-countries` / `GEOIP_COUNTRIES` | a default set | ISO alpha-2 codes for the "interesting" maps |
| `Providers` | `-providers` / `GEOIP_PROVIDERS` | `all` | `aws,gcp,digitalocean,azure` \| `all` \| `none` |
| `SkipValidate` | `-skip-validate` / `GEOIP_SKIP_VALIDATE` | lib `false`, CLI `true` | skip `nft -c` check and reload |
| `NFTablesConfPath` | `-nftables-conf` / `GEOIP_NFTABLES_CONF` | `/etc/nftables.conf` | config used for validation |
| `IncludeDir` | `-include-dir` / `GEOIP_INCLUDE_DIR` | `OutputDir` | include prefix rewritten during validation |
| `MaxMindLicenseKey` | `MAXMIND_LICENSE_KEY` | — | MaxMind license key |
| `SyncInterval` | — | 7 days | `Run` repeat interval |
| `ReloadCommand` | — | `sudo systemctl reload nftables` | run after install |
| `HTTPClient` | — | `&http.Client{Timeout: 60s}` | inject an instrumented transport |
| `Logger` | `-log-level`, `-log-format` | discards / `info`, `text` | `*slog.Logger` |
| `StartSpan` | — | no-op | `SpanHook` — bridge spans to your tracer |
| `OnSync` | — | no-op | `MetricsHook` — record sync duration/result |

CLI: `MAXMIND_LICENSE_KEY=… go run ./cmd/geoip-gen -out /etc/nftables/generated`

### Observability hooks

The library imports no tracing/metrics package; it calls hooks you provide. See
`cmd/geoip-gen` for a minimal OpenTelemetry wiring.

```go
type SpanHook    func(ctx context.Context, name string) (context.Context, func(error))
type MetricsHook func(ctx context.Context, d time.Duration, err error)
```

### Custom datacenter providers

Pass your own via `Config.Providers`, optionally combined with `datacenter.Default()`.

```go
type Provider interface {
    Name() string
    Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error)
}
```

## Generated files

| File | Contents |
|------|----------|
| `geoip-def-all.nft` | all country `define`s, continent numerics, `continent_code` map |
| `geoip-def-<continent>.nft` | per-continent country `define`s |
| `geoip-ipv4-interesting.nft` / `geoip-ipv6-interesting.nft` | CIDR → country-mark maps, filtered to `TrustedCountries` |
| `datacenter-ipv4.nft` / `datacenter-ipv6.nft` | cloud-provider CIDR sets |

Country marks are the ISO 3166-1 numeric code (US → 840); continent marks are 1–6
(africa, asia, europe, americas, oceania, antarctica).

## nftables integration

`include` the generated files into a table and use the maps/sets to mark or filter:

```nft
table inet geoip {
    include "/etc/nftables/generated/geoip-def-all.nft"
    include "/etc/nftables/generated/geoip-ipv4-interesting.nft"
    include "/etc/nftables/generated/geoip-ipv6-interesting.nft"
    include "/etc/nftables/generated/datacenter-ipv4.nft"
    include "/etc/nftables/generated/datacenter-ipv6.nft"

    chain geoip-mark {
        type filter hook prerouting priority mangle; policy accept;
        # Restore the mark for established flows and move on.
        ct state { related, established } ct mark != 0x0 meta mark set ct mark return

        ct state new meta mark set ip  saddr map @geoip4
        ct state new meta mark set ip6 saddr map @geoip6
        # Datacenter mark overrides the country mark so a later rule can target it.
        ct state new ip  saddr @datacenter4 meta mark set 0xdead
        ct state new ip6 saddr @datacenter6 meta mark set 0xdead
    }
}
```

Downstream chains match `meta mark` against the `$<country>` / `$<continent>` defines
(e.g. `meta mark $us accept`, `meta mark $europe ...`) or drop `0xdead` datacenter traffic.

## Data sources

- MaxMind GeoLite2 Country CSV (`MAXMIND_LICENSE_KEY` required)
- AWS `ip-ranges.json`, GCP `cloud.json`, DigitalOcean geo CSV, Azure ServiceTags
