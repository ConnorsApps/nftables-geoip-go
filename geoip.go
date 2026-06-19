// Package geoip downloads MaxMind GeoLite2 country data plus cloud-provider datacenter
// CIDR ranges and renders them into nftables map/set files, optionally validating and
// reloading them, on a schedule.
//
// The library depends only on the standard library. Observability is injected through
// the SpanHook and MetricsHook callbacks, and the HTTP client is supplied by the
// caller, so an instrumented transport (e.g. OpenTelemetry) can be used without this
// module importing any third-party package.
package geoip

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ConnorsApps/nftables-geoip-go/country"
	"github.com/ConnorsApps/nftables-geoip-go/datacenter"
	"github.com/ConnorsApps/nftables-geoip-go/maxmind"
	"github.com/ConnorsApps/nftables-geoip-go/nftables"
)

const (
	defaultSyncInterval = 7 * 24 * time.Hour
	defaultHTTPTimeout  = 60 * time.Second
)

// Config holds the configuration for the GeoIP syncer.
//
// Only OutputDir and MaxMindLicenseKey are required. The remaining fields have
// sensible defaults applied by New, so the zero value of an optional field means
// "use the default".
type Config struct {
	OutputDir         string
	TrustedCountries  []string // ISO alpha-2 codes e.g. ["us", "de"]
	MaxMindLicenseKey string
	SkipValidate      bool

	// Optional dependencies. When nil, a default is used.
	HTTPClient *http.Client // default: &http.Client{Timeout: 60s}
	Logger     *slog.Logger // default: discards all output

	// Optional observability hooks. When nil, a no-op is used.
	StartSpan SpanHook
	OnSync    MetricsHook

	// nftables install settings. Empty values fall back to the defaults below.
	NFTablesConfPath string   // default: /etc/nftables.conf
	IncludeDir       string   // production include prefix replaced during validation; default: OutputDir
	ReloadCommand    []string // default: ["sudo", "systemctl", "reload", "nftables"]

	// Providers selects the datacenter CIDR sources. default: datacenter.Default().
	Providers []datacenter.Provider
	// AllowedDatacenterProviders lists provider names (matching Provider.Name(), e.g.
	// "gcp") whose CIDRs get their own mark instead of the generic blocked-datacenter
	// mark. default: none (every datacenter provider is blocked).
	AllowedDatacenterProviders []string
	// SyncInterval is how often Run repeats after the initial sync. default: 7 days.
	SyncInterval time.Duration
}

// Syncer downloads and installs updated GeoIP data on a schedule.
type Syncer struct {
	cfg                        Config
	trustedAlpha2              map[string]bool
	allowedDatacenterProviders map[string]bool

	client    *http.Client
	log       *slog.Logger
	startSpan SpanHook
	onSync    MetricsHook
}

// New creates a Syncer, applying defaults for any optional Config fields.
func New(cfg Config) *Syncer {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.NFTablesConfPath == "" {
		cfg.NFTablesConfPath = "/etc/nftables.conf"
	}
	if cfg.IncludeDir == "" {
		cfg.IncludeDir = cfg.OutputDir
	}
	if len(cfg.ReloadCommand) == 0 {
		cfg.ReloadCommand = []string{"sudo", "systemctl", "reload", "nftables"}
	}
	if len(cfg.Providers) == 0 {
		cfg.Providers = datacenter.Default()
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = defaultSyncInterval
	}

	trusted := make(map[string]bool, len(cfg.TrustedCountries))
	for _, c := range cfg.TrustedCountries {
		trusted[strings.ToUpper(c)] = true
	}

	allowedDC := make(map[string]bool, len(cfg.AllowedDatacenterProviders))
	for _, p := range cfg.AllowedDatacenterProviders {
		allowedDC[strings.ToLower(p)] = true
	}

	return &Syncer{
		cfg:                        cfg,
		trustedAlpha2:              trusted,
		allowedDatacenterProviders: allowedDC,
		client:                     cfg.HTTPClient,
		log:                        cfg.Logger,
		startSpan:                  cfg.StartSpan,
		onSync:                     cfg.OnSync,
	}
}

// validateConfig checks the required Config fields before a sync touches the network or
// the live nftables config, so library callers get a clear error up front rather than a
// confusing failure deep in the pipeline.
func (s *Syncer) validateConfig() error {
	if s.cfg.MaxMindLicenseKey == "" {
		return fmt.Errorf("MaxMindLicenseKey is required")
	}
	if s.cfg.OutputDir == "" {
		return fmt.Errorf("OutputDir is required")
	}
	if len(s.trustedAlpha2) == 0 {
		return fmt.Errorf("TrustedCountries is required (the interesting maps would otherwise be empty)")
	}
	return nil
}

// Sync runs one full download → validate → install cycle.
func (s *Syncer) Sync(ctx context.Context) (err error) {
	ctx, end := s.span(ctx, "geoip.sync")
	defer func() { end(err) }()

	start := time.Now()
	err = s.doSync(ctx)
	if s.onSync != nil {
		s.onSync(ctx, time.Since(start), err)
	}
	return err
}

func (s *Syncer) doSync(ctx context.Context) error {
	if err := s.validateConfig(); err != nil {
		return err
	}

	s.log.Info("geoip: starting sync")

	mm, err := maxmind.Fetch(ctx, s.client, s.cfg.MaxMindLicenseKey, s.startSpan)
	if err != nil {
		return fmt.Errorf("maxmind download: %w", err)
	}
	s.log.Info("geoip: maxmind parsed", "v4_blocks", len(mm.V4), "v6_blocks", len(mm.V6))

	dcV4, dcV6, providerErrs := datacenter.Fetch(ctx, s.client, s.cfg.Providers, s.startSpan)
	for _, e := range providerErrs {
		s.log.Warn("geoip: datacenter provider fetch failed (continuing)", "error", e)
	}
	s.log.Info("geoip: datacenter fetched", "dc_v4", len(dcV4), "dc_v6", len(dcV6))

	v4Interesting := countInteresting(mm.V4, s.trustedAlpha2)
	v6Interesting := countInteresting(mm.V6, s.trustedAlpha2)

	// Seed every configured provider at 0 before counting so a provider whose fetch
	// errored (and therefore contributed no blocks) is indistinguishable from, and
	// equally caught as, one that fetched successfully but returned nothing.
	datacenterByProvider := make(map[string]int, len(s.cfg.Providers))
	for _, p := range s.cfg.Providers {
		datacenterByProvider[p.Name()] = 0
	}
	for _, b := range dcV4 {
		datacenterByProvider[b.Provider]++
	}
	for _, b := range dcV6 {
		datacenterByProvider[b.Provider]++
	}

	if err := runSanityChecks(
		s.cfg.OutputDir,
		datacenterByProvider,
		v4Interesting, v6Interesting,
		s.trustedAlpha2,
		mm.V4, mm.V6,
	); err != nil {
		return fmt.Errorf("sanity check: %w", err)
	}

	// Don't render or touch the live config if we're being shut down.
	if err := ctx.Err(); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "geoip-*")
	if err != nil {
		return fmt.Errorf("create tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := nftables.Render(tmpDir, nftables.Input{
		V4Blocks:                   mm.V4,
		V6Blocks:                   mm.V6,
		Locations:                  mm.Locations,
		TrustedAlpha2:              s.trustedAlpha2,
		DatacenterV4:               dcV4,
		DatacenterV6:               dcV6,
		AllowedDatacenterProviders: s.allowedDatacenterProviders,
	}); err != nil {
		return fmt.Errorf("generate files: %w", err)
	}

	if err := nftables.Install(ctx, tmpDir, nftables.InstallConfig{
		OutputDir:        s.cfg.OutputDir,
		NFTablesConfPath: s.cfg.NFTablesConfPath,
		IncludeDir:       s.cfg.IncludeDir,
		ReloadCommand:    s.cfg.ReloadCommand,
		SkipValidate:     s.cfg.SkipValidate,
		StartSpan:        s.startSpan,
	}); err != nil {
		return fmt.Errorf("validate/install: %w", err)
	}

	s.log.Info("geoip: sync complete",
		"v4_interesting", v4Interesting,
		"v6_interesting", v6Interesting,
		"dc_v4", len(dcV4),
		"dc_v6", len(dcV6),
	)
	return nil
}

// Run syncs on startup then repeats every SyncInterval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	if err := s.Sync(ctx); err != nil {
		s.log.Error("geoip: initial sync failed", "error", err)
	}

	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sync(ctx); err != nil {
				s.log.Error("geoip: sync failed", "error", err)
			}
		}
	}
}

// countInteresting reports the number of nft map elements that will actually be
// rendered for blocks restricted to trustedAlpha2. This must track whatever
// generateMapFile produces (currently merged ranges, not one element per raw
// block) so callers comparing this count against a previous generation - e.g.
// the regression guard in runSanityChecks - compare like with like.
func countInteresting(blocks []country.Block, trustedAlpha2 map[string]bool) int {
	return nftables.CountMergedElements(blocks, trustedAlpha2)
}
