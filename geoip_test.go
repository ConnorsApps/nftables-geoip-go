package geoip

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/datacenter"
)

// buildTestMaxMindZip produces a minimal GeoLite2 Country CSV bundle with two US/DE
// blocks per family — enough for the trusted-country presence checks once the sanity
// floors are lowered for the test.
func buildTestMaxMindZip(t *testing.T) []byte {
	t.Helper()
	const prefix = "GeoLite2-Country-CSV_20240101/"

	locations := "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n" +
		"6252001,en,NA,North America,US,United States,0\n" +
		"2921044,en,EU,Europe,DE,Germany,1\n"

	v4 := "network,geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n" +
		"10.0.0.0/8,6252001,6252001,0,0\n" +
		"2.16.0.0/24,2921044,2921044,0,0\n"

	v6 := "network,geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n" +
		"2606:4700::/32,6252001,6252001,0,0\n" +
		"2001:db8::/32,2921044,2921044,0,0\n"

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		prefix + "GeoLite2-Country-Locations-en.csv": locations,
		prefix + "GeoLite2-Country-Blocks-IPv4.csv":  v4,
		prefix + "GeoLite2-Country-Blocks-IPv6.csv":  v6,
	} {
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

func TestSync_EndToEnd(t *testing.T) {
	zipBytes := buildTestMaxMindZip(t)

	// A single test server routes by path: the MaxMind download and the one datacenter
	// provider we exercise (AWS).
	awsJSON := `{"prefixes":[{"ip_prefix":"13.34.0.0/16"},{"ip_prefix":"15.230.0.0/16"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "geoip_download"), strings.Contains(r.URL.Path, "geoip_download"):
			w.Write(zipBytes)
		case strings.Contains(r.URL.Path, "aws"):
			w.Write([]byte(awsJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// maxmind.Fetch uses a hardcoded download.maxmind.com URL, so route every request
	// through the test server regardless of host. Routing then keys off path/query.
	base, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{base: base}}

	outDir := t.TempDir()
	s := New(Config{
		OutputDir:         outDir,
		TrustedCountries:  []string{"us", "de"},
		MaxMindLicenseKey: "test-key",
		SkipValidate:      true, // no nft binary in CI
		HTTPClient:        client,
		Providers:         []datacenter.Provider{testAWS{url: srv.URL + "/aws"}},
	})

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// The full set of generated files should exist.
	for _, name := range []string{
		"geoip-def-all.nft",
		"geoip-ipv4-interesting.nft",
		"geoip-ipv6-interesting.nft",
		"datacenter-ipv4.nft",
		"datacenter-ipv6.nft",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("expected generated file %s: %v", name, err)
		}
	}

	// Trusted-country blocks made it into the interesting maps.
	v4 := readFile(t, outDir, "geoip-ipv4-interesting.nft")
	if !strings.Contains(v4, "10.0.0.0/8 : $US") || !strings.Contains(v4, "2.16.0.0/24 : $DE") {
		t.Errorf("ipv4 interesting map missing expected entries:\n%s", v4)
	}

	// AWS is not in the default AllowedDatacenterProviders, so its prefix renders with
	// the generic blocked mark, not its own.
	dc4 := readFile(t, outDir, "datacenter-ipv4.nft")
	if !strings.Contains(dc4, "13.34.0.0/16 : 0xdead") {
		t.Errorf("datacenter ipv4 map missing blocked AWS prefix:\n%s", dc4)
	}
}

func TestSync_AllowedDatacenterProviderGetsOwnMark(t *testing.T) {
	zipBytes := buildTestMaxMindZip(t)
	awsJSON := `{"prefixes":[{"ip_prefix":"13.34.0.0/16"}],"ipv6_prefixes":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "geoip_download"), strings.Contains(r.URL.Path, "geoip_download"):
			w.Write(zipBytes)
		case strings.Contains(r.URL.Path, "aws"):
			w.Write([]byte(awsJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{base: base}}

	outDir := t.TempDir()
	s := New(Config{
		OutputDir:                  outDir,
		TrustedCountries:           []string{"us", "de"},
		MaxMindLicenseKey:          "test-key",
		SkipValidate:               true,
		HTTPClient:                 client,
		Providers:                  []datacenter.Provider{testAWS{url: srv.URL + "/aws"}},
		AllowedDatacenterProviders: []string{"aws"},
	})

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	dc4 := readFile(t, outDir, "datacenter-ipv4.nft")
	if !strings.Contains(dc4, "13.34.0.0/16 : $AWS") {
		t.Errorf("datacenter ipv4 map missing allowed AWS prefix with its own mark:\n%s", dc4)
	}
}

// rewriteTransport sends every request to base, preserving the original path and query
// so the test handler can route on them. It lets the test intercept the hardcoded
// MaxMind download URL without changing production code.
type rewriteTransport struct{ base *url.URL }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.base.Scheme
	req.URL.Host = rt.base.Host
	req.Host = rt.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// testAWS fetches an AWS-shaped ip-ranges payload from a test URL, exercising the
// datacenter fetch/aggregate path without reaching the live AWS endpoint.
type testAWS struct{ url string }

func (testAWS) Name() string { return "aws" }

func (a testAWS) Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	var payload struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, err
	}
	for _, p := range payload.Prefixes {
		if pfx, err := netip.ParsePrefix(p.IPPrefix); err == nil {
			v4 = append(v4, pfx)
		}
	}
	for _, p := range payload.IPv6Prefixes {
		if pfx, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
			v6 = append(v6, pfx)
		}
	}
	return v4, v6, nil
}
