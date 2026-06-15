package maxmind

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

// buildMaxMindZip writes a minimal GeoLite2 Country CSV bundle into a zip, mimicking
// the dated directory prefix MaxMind uses on its entries.
func buildMaxMindZip(t *testing.T, locations, blocksV4, blocksV6 string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	const prefix = "GeoLite2-Country-CSV_20240101/"
	files := map[string]string{
		prefix + "GeoLite2-Country-Locations-en.csv": locations,
		prefix + "GeoLite2-Country-Blocks-IPv4.csv":  blocksV4,
		prefix + "GeoLite2-Country-Blocks-IPv6.csv":  blocksV6,
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestParse(t *testing.T) {
	locations := "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
		"6252001,en,NA,North America,US,United States,0\n" +
		"2921044,en,EU,Europe,DE,Germany,1\n" +
		// continent-level entry (no country code) — must be skipped
		"6255149,en,NA,North America,,,0\n"

	blocksV4 := "network,geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n" +
		"10.0.0.0/8,6252001,6252001,0,0\n" +
		"2.16.0.0/24,2921044,2921044,0,0\n" +
		// geoname_id maps to an unknown location — skipped
		"5.5.5.0/24,9999999,9999999,0,0\n" +
		// empty geoname_id falls back to registered_country_geoname_id
		"8.8.8.0/24,,6252001,0,0\n"

	blocksV6 := "network,geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n" +
		"2001:db8::/32,2921044,2921044,0,0\n"

	zipBytes := buildMaxMindZip(t, locations, blocksV4, blocksV6)

	res, err := Parse(zipBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Two valid locations (US, DE); the continent-level row is dropped.
	if len(res.Locations) != 2 {
		t.Errorf("locations = %d, want 2", len(res.Locations))
	}

	// US (10.0.0.0/8 + 8.8.8.0/24 via fallback) and DE (2.16.0.0/24); unknown id dropped.
	if len(res.V4) != 3 {
		t.Fatalf("v4 blocks = %d, want 3", len(res.V4))
	}
	if len(res.V6) != 1 {
		t.Fatalf("v6 blocks = %d, want 1", len(res.V6))
	}

	byNet := map[string]country.Block{}
	for _, b := range res.V4 {
		byNet[b.Network.String()] = b
	}
	if b, ok := byNet["10.0.0.0/8"]; !ok || b.Alpha2 != "US" || b.Numeric != 840 {
		t.Errorf("10.0.0.0/8 = %+v, want US/840", b)
	}
	if b, ok := byNet["2.16.0.0/24"]; !ok || b.Alpha2 != "DE" || b.Numeric != 276 {
		t.Errorf("2.16.0.0/24 = %+v, want DE/276", b)
	}
	if b, ok := byNet["8.8.8.0/24"]; !ok || b.Alpha2 != "US" {
		t.Errorf("8.8.8.0/24 fallback = %+v, want US", b)
	}

	if res.V6[0].Alpha2 != "DE" {
		t.Errorf("v6[0] alpha2 = %q, want DE", res.V6[0].Alpha2)
	}

	// Continent mapping comes through the locations table.
	for _, info := range res.Locations {
		switch info.Alpha2 {
		case "US":
			if info.Continent != "americas" {
				t.Errorf("US continent = %q, want americas", info.Continent)
			}
		case "DE":
			if info.Continent != "europe" {
				t.Errorf("DE continent = %q, want europe", info.Continent)
			}
		}
	}
}

// errRoundTripper fails every request, mimicking a transport-level error. net/http
// wraps the returned error in a *url.Error that embeds the full request URL.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("simulated dial failure")
}

func TestFetchRedactsLicenseKey(t *testing.T) {
	const key = "super-secret-license-key"
	client := &http.Client{Transport: errRoundTripper{}}

	_, err := Fetch(context.Background(), client, key, nil)
	if err == nil {
		t.Fatal("expected an error from the failing transport")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("license key leaked into error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("expected REDACTED placeholder in error, got %q", err.Error())
	}
}

func TestRedactKey(t *testing.T) {
	err := fmt.Errorf(`Get "https://download.maxmind.com/?license_key=abc123": dial failed`)
	got := redactKey(err, "abc123")
	if strings.Contains(got.Error(), "abc123") {
		t.Fatalf("key not redacted: %q", got.Error())
	}
	// Empty key and nil error are passed through unchanged.
	if redactKey(nil, "abc123") != nil {
		t.Error("nil error should stay nil")
	}
	if got := redactKey(err, ""); got != err {
		t.Error("empty key should return the original error unchanged")
	}
}

func TestParseBadData(t *testing.T) {
	if _, err := Parse([]byte("not a zip")); err == nil {
		t.Fatal("expected error for non-zip input")
	}
}

func TestISONumericByAlpha2(t *testing.T) {
	cases := map[string]uint32{
		"US": 840,
		"DE": 276,
		"FR": 250,
		"GB": 826,
		"JP": 392,
	}
	for alpha2, want := range cases {
		if got := isoNumericByAlpha2[alpha2]; got != want {
			t.Errorf("isoNumericByAlpha2[%q] = %d, want %d", alpha2, got, want)
		}
	}
}

func TestContinentNameByMaxMindCode(t *testing.T) {
	cases := map[string]string{
		"AF": "africa",
		"AN": "antarctica",
		"AS": "asia",
		"EU": "europe",
		"NA": "americas",
		"OC": "oceania",
		"SA": "americas", // South America folds into "americas"
	}
	for code, want := range cases {
		if got := continentNameByMaxMindCode[code]; got != want {
			t.Errorf("continentNameByMaxMindCode[%q] = %q, want %q", code, got, want)
		}
	}
}
