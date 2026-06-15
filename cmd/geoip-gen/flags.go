package main

import (
	"flag"
	"os"
	"strconv"
)

// flags holds the parsed command-line options.
type flags struct {
	*flag.FlagSet

	out          string
	countries    string
	providers    string
	skipValidate bool
	nftablesConf string
	includeDir   string
	logLevel     string
	logFormat    string
}

const defaultCountries = "us,de,fr,ch,es,it,gr,gb,se,no,fi,ca,dk,is,pl,pt"

// newFlagSet defines the CLI flags. Each flag defaults to its environment variable
// (GEOIP_*) when set, so the same options can be supplied either way; the flag wins
// when both are provided.
func newFlagSet() *flags {
	fs := &flags{FlagSet: flag.NewFlagSet("geoip-gen", flag.ContinueOnError)}

	fs.StringVar(&fs.out, "out", env("GEOIP_OUTPUT_DIR", "."),
		"output directory for generated .nft files [GEOIP_OUTPUT_DIR]")
	fs.StringVar(&fs.countries, "countries", env("GEOIP_COUNTRIES", defaultCountries),
		"comma-separated trusted country ISO alpha-2 codes [GEOIP_COUNTRIES]")
	fs.StringVar(&fs.providers, "providers", env("GEOIP_PROVIDERS", "all"),
		"comma-separated datacenter providers: aws,gcp,digitalocean,azure | all | none [GEOIP_PROVIDERS]")
	fs.BoolVar(&fs.skipValidate, "skip-validate", envBool("GEOIP_SKIP_VALIDATE", true),
		"skip the `nft -c` validation and reload (for machines without nftables) [GEOIP_SKIP_VALIDATE]")
	fs.StringVar(&fs.nftablesConf, "nftables-conf", env("GEOIP_NFTABLES_CONF", ""),
		"path to the nftables config used for validation (default /etc/nftables.conf) [GEOIP_NFTABLES_CONF]")
	fs.StringVar(&fs.includeDir, "include-dir", env("GEOIP_INCLUDE_DIR", ""),
		"production include prefix rewritten during validation (default: -out) [GEOIP_INCLUDE_DIR]")
	fs.StringVar(&fs.logLevel, "log-level", env("GEOIP_LOG_LEVEL", "info"),
		"log level: debug, info, warn, error [GEOIP_LOG_LEVEL]")
	fs.StringVar(&fs.logFormat, "log-format", env("GEOIP_LOG_FORMAT", "text"),
		"log format: text or json [GEOIP_LOG_FORMAT]")

	return fs
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
