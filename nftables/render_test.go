package nftables

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/country"
	"github.com/ConnorsApps/nftables-geoip-go/datacenter"
)

func readGen(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func trustedSet(codes ...string) map[string]bool {
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		m[c] = true
	}
	return m
}

func TestGenerateMapFile(t *testing.T) {
	dir := t.TempDir()
	blocks := []country.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Alpha2: "US"},
		{Network: netip.MustParsePrefix("2.16.0.0/24"), Alpha2: "DE"},
	}

	if err := generateMapFile(dir, "geoip-ipv4.nft", "geoip4", "ipv4_addr", blocks, nil); err != nil {
		t.Fatal(err)
	}
	// mergeBlocks sorts by address, so the lower-numbered 2.16.0.0/24 block sorts
	// before 10.0.0.0/8 regardless of input order.
	want := "map geoip4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t2.16.0.0/24 : $DE,\n" +
		"\t\t10.0.0.0/8 : $US\n" +
		"\t}\n}\n"
	if got := readGen(t, dir, "geoip-ipv4.nft"); got != want {
		t.Errorf("unfiltered map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerateMapFileFiltered(t *testing.T) {
	dir := t.TempDir()
	blocks := []country.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Alpha2: "US"},
		{Network: netip.MustParsePrefix("2.16.0.0/24"), Alpha2: "DE"},
	}

	if err := generateMapFile(dir, "interesting.nft", "geoip4", "ipv4_addr", blocks, trustedSet("US")); err != nil {
		t.Fatal(err)
	}
	want := "map geoip4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t10.0.0.0/8 : $US\n" +
		"\t}\n}\n"
	if got := readGen(t, dir, "interesting.nft"); got != want {
		t.Errorf("filtered map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerateMapFileEmpty(t *testing.T) {
	dir := t.TempDir()
	blocks := []country.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Alpha2: "US"},
	}

	// Filter excludes every block, so no elements should be written. An empty
	// `elements = {}` block would be invalid nft.
	if err := generateMapFile(dir, "empty.nft", "geoip4", "ipv4_addr", blocks, trustedSet("DE")); err != nil {
		t.Fatal(err)
	}
	want := "map geoip4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"}\n"
	if got := readGen(t, dir, "empty.nft"); got != want {
		t.Errorf("empty map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerateDatacenterMapEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := generateDatacenterMap(dir, "empty.nft", "datacenter4", "ipv4_addr", nil, nil); err != nil {
		t.Fatal(err)
	}
	want := "map datacenter4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"}\n"
	if got := readGen(t, dir, "empty.nft"); got != want {
		t.Errorf("empty map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerateDatacenterMap_UnknownProviderFallsBackToDead(t *testing.T) {
	dir := t.TempDir()
	blocks := []datacenter.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Provider: "aws"},
		{Network: netip.MustParsePrefix("192.168.0.0/16"), Provider: "azure"},
	}

	// No allowed providers: everything falls back to the generic blocked mark.
	if err := generateDatacenterMap(dir, "datacenter-ipv4.nft", "datacenter4", "ipv4_addr", blocks, nil); err != nil {
		t.Fatal(err)
	}
	want := "map datacenter4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t10.0.0.0/8 : 0xdead,\n" +
		"\t\t192.168.0.0/16 : 0xdead\n" +
		"\t}\n}\n"
	if got := readGen(t, dir, "datacenter-ipv4.nft"); got != want {
		t.Errorf("datacenter map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerateDatacenterMap_GCPAllowed(t *testing.T) {
	dir := t.TempDir()
	blocks := []datacenter.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Provider: "aws"},
		{Network: netip.MustParsePrefix("34.64.0.0/10"), Provider: "gcp"},
	}

	if err := generateDatacenterMap(dir, "datacenter-ipv4.nft", "datacenter4", "ipv4_addr", blocks, map[string]bool{"gcp": true}); err != nil {
		t.Fatal(err)
	}
	want := "map datacenter4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t10.0.0.0/8 : 0xdead,\n" +
		"\t\t34.64.0.0/10 : $GCP\n" +
		"\t}\n}\n"
	if got := readGen(t, dir, "datacenter-ipv4.nft"); got != want {
		t.Errorf("datacenter map mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestMergeDatacenterBlocks_DoesNotMergeAcrossProviders(t *testing.T) {
	// Adjacent CIDRs from different providers must not merge into one range, even
	// though they're contiguous in address space.
	blocks := []datacenter.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/24"), Provider: "aws"},
		{Network: netip.MustParsePrefix("10.0.1.0/24"), Provider: "gcp"},
	}
	got := mergeDatacenterBlocks(blocks)
	if len(got) != 2 {
		t.Fatalf("got %d merged ranges, want 2 (no cross-provider merge)", len(got))
	}
}

func TestMergeDatacenterBlocks_MergesAdjacentSameProvider(t *testing.T) {
	blocks := []datacenter.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/24"), Provider: "gcp"},
		{Network: netip.MustParsePrefix("10.0.1.0/24"), Provider: "gcp"},
	}
	got := mergeDatacenterBlocks(blocks)
	if len(got) != 1 {
		t.Fatalf("got %d merged ranges, want 1 (adjacent same-provider blocks merge)", len(got))
	}
	if got[0].Single() {
		t.Errorf("merged range should not report Single() once coalesced")
	}
}

func TestGenerateDefFiles(t *testing.T) {
	dir := t.TempDir()
	locs := country.Locations{
		"1": {Alpha2: "US", Numeric: 840, Continent: "americas"},
		"2": {Alpha2: "DE", Numeric: 276, Continent: "europe"},
		"3": {Alpha2: "JP", Numeric: 392, Continent: "asia"},
	}
	if err := generateDefFiles(dir, locs); err != nil {
		t.Fatal(err)
	}

	// Per-continent file contains only that continent's countries.
	if got, want := readGen(t, dir, "geoip-def-europe.nft"), "define DE = 276\n"; got != want {
		t.Errorf("europe def = %q, want %q", got, want)
	}

	all := readGen(t, dir, "geoip-def-all.nft")
	// Country defines are sorted by alpha-2.
	if !strings.HasPrefix(all, "define DE = 276\ndefine JP = 392\ndefine US = 840\n") {
		t.Errorf("geoip-def-all.nft does not start with sorted country defines:\n%q", all)
	}
	for _, want := range []string{
		"define americas = 4\n",
		"map continent_code {",
		"\t\t$US : $americas",
		"\t\t$DE : $europe,",
		"\t\t$JP : $asia,",
		"define GCP = 55810\n",
		"define AWS = 55809\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("geoip-def-all.nft missing %q", want)
		}
	}
}
