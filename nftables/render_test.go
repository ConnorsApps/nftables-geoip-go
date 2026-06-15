package nftables

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

func readGen(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		out[i] = p
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

func TestGenerateMapFile(t *testing.T) {
	dir := t.TempDir()
	blocks := []country.Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Alpha2: "US"},
		{Network: netip.MustParsePrefix("2.16.0.0/24"), Alpha2: "DE"},
	}

	if err := generateMapFile(dir, "geoip-ipv4.nft", "geoip4", "ipv4_addr", blocks, nil); err != nil {
		t.Fatal(err)
	}
	want := "map geoip4 {\n" +
		"\ttype ipv4_addr : mark\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t10.0.0.0/8 : $US,\n" +
		"\t\t2.16.0.0/24 : $DE\n" +
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

func TestGenerateDatacenterSet(t *testing.T) {
	dir := t.TempDir()
	pfxs := prefixes(t, "10.0.0.0/8", "192.168.0.0/16")

	if err := generateDatacenterSet(dir, "datacenter-ipv4.nft", "datacenter4", "ipv4_addr", pfxs); err != nil {
		t.Fatal(err)
	}
	want := "set datacenter4 {\n" +
		"\ttype ipv4_addr\n" +
		"\tflags interval\n" +
		"\telements = {\n" +
		"\t\t10.0.0.0/8,\n" +
		"\t\t192.168.0.0/16\n" +
		"\t}\n}\n"
	if got := readGen(t, dir, "datacenter-ipv4.nft"); got != want {
		t.Errorf("datacenter set mismatch:\n got: %q\nwant: %q", got, want)
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
	} {
		if !strings.Contains(all, want) {
			t.Errorf("geoip-def-all.nft missing %q", want)
		}
	}
}
