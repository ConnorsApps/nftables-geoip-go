package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

// blocksFor returns one country.Block per country code (network value is irrelevant to
// the sanity checks, which only inspect Alpha2).
func blocksFor(codes ...string) []country.Block {
	out := make([]country.Block, len(codes))
	for i, c := range codes {
		out[i] = country.Block{Network: netip.MustParsePrefix("10.0.0.0/8"), Alpha2: c}
	}
	return out
}

func trustedSet(codes ...string) map[string]bool {
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		m[c] = true
	}
	return m
}

func TestRunSanityChecks_Pass(t *testing.T) {
	dir := t.TempDir() // empty: first run, no regression baseline
	trusted := trustedSet("US", "DE")
	err := runSanityChecks(dir,
		minIPv4InterestingEntries+1, minIPv6InterestingEntries+1,
		minDatacenterPrefixes+1,
		trusted,
		blocksFor("US", "DE"), blocksFor("US", "DE"),
	)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestRunSanityChecks_FloorFailures(t *testing.T) {
	dir := t.TempDir()
	trusted := trustedSet("US")
	blocks := blocksFor("US")

	cases := []struct {
		name       string
		v4, v6, dc int
		wantSubstr string
	}{
		{"v4 floor", minIPv4InterestingEntries - 1, minIPv6InterestingEntries + 1, minDatacenterPrefixes + 1, "IPv4 interesting"},
		{"v6 floor", minIPv4InterestingEntries + 1, minIPv6InterestingEntries - 1, minDatacenterPrefixes + 1, "IPv6 interesting"},
		{"datacenter floor", minIPv4InterestingEntries + 1, minIPv6InterestingEntries + 1, minDatacenterPrefixes - 1, "datacenter CIDR count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runSanityChecks(dir, tc.v4, tc.v6, tc.dc, trusted, blocks, blocks)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestRunSanityChecks_TrustedCountryMissing(t *testing.T) {
	dir := t.TempDir()
	trusted := trustedSet("US", "DE")
	// DE is absent from the IPv4 blocks, so the IPv4 presence check must trip.
	err := runSanityChecks(dir,
		minIPv4InterestingEntries+1, minIPv6InterestingEntries+1,
		minDatacenterPrefixes+1,
		trusted,
		blocksFor("US"), blocksFor("US", "DE"),
	)
	if err == nil || !strings.Contains(err.Error(), "missing from IPv4") {
		t.Fatalf("got %v, want a trusted-country-missing error", err)
	}
}

func TestRunSanityChecks_TrustedCountryMissingV6(t *testing.T) {
	dir := t.TempDir()
	trusted := trustedSet("US", "DE")
	// DE is present in IPv4 but absent from IPv6, so the IPv6 presence check must trip.
	err := runSanityChecks(dir,
		minIPv4InterestingEntries+1, minIPv6InterestingEntries+1,
		minDatacenterPrefixes+1,
		trusted,
		blocksFor("US", "DE"), blocksFor("US"),
	)
	if err == nil || !strings.Contains(err.Error(), "missing from IPv6") {
		t.Fatalf("got %v, want an IPv6 trusted-country-missing error", err)
	}
}

func TestRunSanityChecks_RegressionGuard(t *testing.T) {
	dir := t.TempDir()
	// Seed an existing interesting map with 100k entries (lines containing " : $").
	const existing = 100_000
	seed := strings.Repeat("\t\t10.0.0.0/8 : $US,\n", existing)
	if err := os.WriteFile(filepath.Join(dir, "geoip-ipv4-interesting.nft"), []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}

	trusted := trustedSet("US")
	blocks := blocksFor("US")

	// New count clears the absolute floor but is far below 90% of the existing 100k.
	newCount := minIPv4InterestingEntries + 1
	err := runSanityChecks(dir, newCount, minIPv6InterestingEntries+1, minDatacenterPrefixes+1, trusted, blocks, blocks)
	if err == nil || !strings.Contains(err.Error(), "90%") {
		t.Fatalf("got %v, want a regression (90%%) error", err)
	}
}
