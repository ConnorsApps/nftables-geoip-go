package geoip

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ConnorsApps/nftables-geoip-go/country"
	"github.com/ConnorsApps/nftables-geoip-go/nftables"
)

// regressionThreshold is the fraction of the previously-installed entry count a new
// generation must reach. It self-calibrates to whatever a given deployment's normal size
// is, so unlike an absolute floor it works for both small and large trusted sets.
const regressionThreshold = 0.90

// runSanityChecks verifies the generated data is plausible before replacing live files.
//
// It deliberately avoids absolute floor counts (e.g. "at least 50k entries"), which bake
// in an assumption about deployment scale and would reject a legitimately small trusted
// set. Instead it relies on two self-scaling checks — the regression guard against the
// last good install, and trusted-country presence — plus a total-failure guard on the
// datacenter fetch.
func runSanityChecks(
	destDir string,
	providerCount int,
	v4InterestingCount, v6InterestingCount int,
	datacenterCount int,
	trustedAlpha2 map[string]bool,
	v4Blocks, v6Blocks []country.Block,
) error {
	// Total-failure guard: if providers are configured but every fetch produced nothing,
	// installing would wipe the datacenter sets. A deliberately empty provider list is fine.
	if providerCount > 0 && datacenterCount == 0 {
		return fmt.Errorf("datacenter CIDR count is 0 with %d providers configured (total provider fetch failure?)", providerCount)
	}

	// Regression guard: new count must be >= 90% of existing deployed count.
	for _, name := range []string{"geoip-ipv4-interesting.nft", "geoip-ipv6-interesting.nft"} {
		existingPath := filepath.Join(destDir, name)
		existing, err := nftables.CountMapEntries(existingPath)
		if err != nil {
			return fmt.Errorf("count existing entries in %s: %w", name, err)
		}
		if existing == 0 {
			continue // first run, no baseline
		}
		var newCount int
		if strings.Contains(name, "ipv4") {
			newCount = v4InterestingCount
		} else {
			newCount = v6InterestingCount
		}
		threshold := int(float64(existing) * regressionThreshold)
		if newCount < threshold {
			return fmt.Errorf("%s: new entry count %d < 90%% of existing %d (%d) - partial download?",
				name, newCount, existing, threshold)
		}
	}

	// All trusted countries must appear in the interesting maps. This also implies the
	// interesting counts are non-zero for a non-empty trusted set, so no separate floor
	// check is needed.
	presentV4 := make(map[string]bool)
	for _, b := range v4Blocks {
		if trustedAlpha2[b.Alpha2] {
			presentV4[b.Alpha2] = true
		}
	}
	presentV6 := make(map[string]bool)
	for _, b := range v6Blocks {
		if trustedAlpha2[b.Alpha2] {
			presentV6[b.Alpha2] = true
		}
	}

	for alpha2 := range trustedAlpha2 {
		if !presentV4[alpha2] {
			return fmt.Errorf("trusted country %s missing from IPv4 interesting map", alpha2)
		}
		if !presentV6[alpha2] {
			return fmt.Errorf("trusted country %s missing from IPv6 interesting map", alpha2)
		}
	}

	return nil
}
