package geoip

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ConnorsApps/nftables-geoip-go/country"
	"github.com/ConnorsApps/nftables-geoip-go/nftables"
)

const (
	minIPv4InterestingEntries = 50_000
	minIPv6InterestingEntries = 20_000
	minDatacenterPrefixes     = 1_000
	regressionThreshold       = 0.90
)

// runSanityChecks verifies the generated files are plausible before replacing live ones.
func runSanityChecks(
	destDir string,
	v4InterestingCount, v6InterestingCount int,
	datacenterCount int,
	trustedAlpha2 map[string]bool,
	v4Blocks, v6Blocks []country.Block,
) error {
	// Absolute floor checks.
	if v4InterestingCount < minIPv4InterestingEntries {
		return fmt.Errorf("IPv4 interesting entries %d < minimum %d (catastrophic truncation?)", v4InterestingCount, minIPv4InterestingEntries)
	}
	if v6InterestingCount < minIPv6InterestingEntries {
		return fmt.Errorf("IPv6 interesting entries %d < minimum %d (catastrophic truncation?)", v6InterestingCount, minIPv6InterestingEntries)
	}

	// Datacenter set non-empty.
	if datacenterCount < minDatacenterPrefixes {
		return fmt.Errorf("datacenter CIDR count %d < minimum %d (total provider fetch failure?)", datacenterCount, minDatacenterPrefixes)
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

	// All trusted countries must appear in the interesting maps.
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
