// geoip-gen generates the nftables GeoIP .nft files from MaxMind GeoLite2 data plus
// cloud-provider datacenter CIDR ranges.
//
// A MaxMind license key is required, supplied via the MAXMIND_LICENSE_KEY environment
// variable. Every flag may also be set from an environment variable (see each flag's
// usage); the flag takes precedence when both are given.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	geoip "github.com/ConnorsApps/nftables-geoip-go"
	"github.com/ConnorsApps/nftables-geoip-go/datacenter"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "geoip-gen:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := newFlagSet()
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	licenseKey := os.Getenv("MAXMIND_LICENSE_KEY")
	if licenseKey == "" {
		return fmt.Errorf("MAXMIND_LICENSE_KEY env var is required")
	}

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(fs.logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q: %w", fs.logLevel, err)
	}
	logger := slog.New(newLogHandler(fs.logFormat, level))

	providers, err := selectProviders(fs.providers)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(fs.out, 0o755); err != nil {
		return fmt.Errorf("create output directory %q: %w", fs.out, err)
	}

	cfg := geoip.Config{
		OutputDir:         fs.out,
		TrustedCountries:  splitCSV(fs.countries),
		MaxMindLicenseKey: licenseKey,
		SkipValidate:      fs.skipValidate,
		Logger:            logger,
		Providers:         providers,
		NFTablesConfPath:  fs.nftablesConf,
		IncludeDir:        fs.includeDir,
	}

	if err := geoip.New(cfg).Sync(context.Background()); err != nil {
		return err
	}
	logger.Info("geoip-gen: done", "out", fs.out)
	return nil
}

// selectProviders maps a comma-separated list of provider names to providers. "all"
// (or empty) returns the built-in defaults; "none" returns an empty, non-nil slice.
func selectProviders(spec string) ([]datacenter.Provider, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return nil, nil // let geoip apply datacenter.Default()
	}
	if spec == "none" {
		return []datacenter.Provider{}, nil
	}
	byName := map[string]datacenter.Provider{
		"aws":          datacenter.AWS{},
		"gcp":          datacenter.GCP{},
		"digitalocean": datacenter.DigitalOcean{},
		"azure":        datacenter.Azure{},
	}
	var out []datacenter.Provider
	for _, name := range splitCSV(spec) {
		p, ok := byName[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown provider %q (valid: aws, gcp, digitalocean, azure, all, none)", name)
		}
		out = append(out, p)
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func newLogHandler(format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(format, "json") {
		return slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.NewTextHandler(os.Stdout, opts)
}
