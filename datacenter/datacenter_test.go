package datacenter

import (
	"context"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
)

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

// blocksOf attributes every prefix to the given provider, for tests that don't care
// about cross-provider behavior.
func blocksOf(t *testing.T, provider string, cidrs ...string) []Block {
	t.Helper()
	pfxs := prefixes(t, cidrs...)
	out := make([]Block, len(pfxs))
	for i, p := range pfxs {
		out[i] = Block{Network: p, Provider: provider, Code: codeByProvider[provider]}
	}
	return out
}

func networksOf(blocks []Block) []netip.Prefix {
	out := make([]netip.Prefix, len(blocks))
	for i, b := range blocks {
		out[i] = b.Network
	}
	return out
}

func TestAggregateBlocks(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "drops exact duplicate",
			in:   []string{"10.0.0.0/8", "10.0.0.0/8"},
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "drops prefix covered by a wider one",
			in:   []string{"10.1.0.0/16", "10.0.0.0/8"},
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "keeps disjoint prefixes sorted",
			in:   []string{"192.168.0.0/16", "10.0.0.0/8"},
			want: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name: "mixed overlap and disjoint",
			in:   []string{"10.0.0.0/8", "10.1.2.0/24", "192.168.0.0/16", "10.0.0.0/8"},
			want: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name: "ipv6 overlap",
			in:   []string{"2001:db8::/48", "2001:db8::/32"},
			want: []string{"2001:db8::/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := networksOf(AggregateBlocks(blocksOf(t, "gcp", tt.in...)))
			if len(tt.want) == 0 {
				if len(got) != 0 {
					t.Errorf("AggregateBlocks(%v) = %v, want empty", tt.in, got)
				}
				return
			}
			want := prefixes(t, tt.want...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("AggregateBlocks(%v) = %v, want %v", tt.in, got, want)
			}
		})
	}
}

func TestAggregateBlocks_CrossProviderOverlapFirstWins(t *testing.T) {
	// Two different providers publishing the same prefix should never happen in
	// practice, but must resolve deterministically: sort order (address, then
	// prefix length) decides, same as the same-provider case.
	blocks := []Block{
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Provider: "aws", Code: CodeAWS},
		{Network: netip.MustParsePrefix("10.0.0.0/8"), Provider: "gcp", Code: CodeGCP},
	}
	got := AggregateBlocks(blocks)
	if len(got) != 1 {
		t.Fatalf("got %d blocks, want 1", len(got))
	}
	if got[0].Provider != "aws" {
		t.Errorf("provider = %q, want %q (first in sort order)", got[0].Provider, "aws")
	}
}

func TestFetch_AttributesProviderAndCode(t *testing.T) {
	v4, _, errs := Fetch(context.Background(), http.DefaultClient, []Provider{fakeProvider{name: "gcp", v4: prefixes(t, "34.0.0.0/8")}}, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(v4) != 1 {
		t.Fatalf("got %d blocks, want 1", len(v4))
	}
	if v4[0].Provider != "gcp" || v4[0].Code != CodeGCP {
		t.Errorf("got Provider=%q Code=%#x, want Provider=gcp Code=%#x", v4[0].Provider, v4[0].Code, CodeGCP)
	}
}

func TestFetch_UnknownProviderGetsZeroCode(t *testing.T) {
	v4, _, errs := Fetch(context.Background(), http.DefaultClient, []Provider{fakeProvider{name: "custom-feed", v4: prefixes(t, "203.0.113.0/24")}}, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(v4) != 1 {
		t.Fatalf("got %d blocks, want 1", len(v4))
	}
	if v4[0].Code != 0 {
		t.Errorf("got Code=%#x for unknown provider, want 0", v4[0].Code)
	}
}

type fakeProvider struct {
	name string
	v4   []netip.Prefix
}

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) Fetch(ctx context.Context, client *http.Client) ([]netip.Prefix, []netip.Prefix, error) {
	return f.v4, nil, nil
}

func TestParseAWS(t *testing.T) {
	body := []byte(`{
		"prefixes": [
			{"ip_prefix": "10.0.0.0/8"},
			{"ip_prefix": "192.168.1.0/24"}
		],
		"ipv6_prefixes": [
			{"ipv6_prefix": "2600:1f00::/24"}
		]
	}`)
	v4, v6, err := parseAWS(body)
	if err != nil {
		t.Fatalf("parseAWS: %v", err)
	}
	if got, want := len(v4), 2; got != want {
		t.Errorf("v4 count = %d, want %d", got, want)
	}
	if got, want := len(v6), 1; got != want {
		t.Errorf("v6 count = %d, want %d", got, want)
	}
	if v4[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("v4[0] = %v", v4[0])
	}
}

func TestParseGCP(t *testing.T) {
	body := []byte(`{
		"prefixes": [
			{"ipv4Prefix": "34.0.0.0/16"},
			{"ipv6Prefix": "2600:1900::/28"},
			{}
		]
	}`)
	v4, v6, err := parseGCP(body)
	if err != nil {
		t.Fatalf("parseGCP: %v", err)
	}
	if len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("got v4=%d v6=%d, want 1 and 1", len(v4), len(v6))
	}
	if v4[0] != netip.MustParsePrefix("34.0.0.0/16") {
		t.Errorf("v4[0] = %v", v4[0])
	}
}

func TestParseDigitalOceanCSV(t *testing.T) {
	// First column is the CIDR; remaining columns (country, region, etc.) are ignored.
	body := []byte("1.2.3.0/24,US,CA,San Francisco,94124\n" +
		"2604:a880::/32,US,NY,New York,10001\n" +
		"not-a-cidr,XX\n")
	v4, v6, err := parseDigitalOceanCSV(body)
	if err != nil {
		t.Fatalf("parseDigitalOceanCSV: %v", err)
	}
	if len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("got v4=%d v6=%d, want 1 and 1", len(v4), len(v6))
	}
	if v4[0] != netip.MustParsePrefix("1.2.3.0/24") {
		t.Errorf("v4[0] = %v", v4[0])
	}
}

func TestParseAzureServiceTags(t *testing.T) {
	body := []byte(`{
		"values": [
			{"properties": {"addressPrefixes": ["20.0.0.0/8", "2603:1000::/24"]}},
			{"properties": {"addressPrefixes": ["40.64.0.0/10", "bogus"]}}
		]
	}`)
	v4, v6, err := parseAzureServiceTags(body)
	if err != nil {
		t.Fatalf("parseAzureServiceTags: %v", err)
	}
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("got v4=%d v6=%d, want 2 and 1", len(v4), len(v6))
	}
}

func TestAzureURLRegex(t *testing.T) {
	page := []byte(`<a href="https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20240101.json" class="dl">`)
	match := azureURLRe.Find(page)
	if match == nil {
		t.Fatal("expected a match for the ServiceTags URL")
	}
	want := "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20240101.json"
	if string(match) != want {
		t.Errorf("matched %q, want %q", match, want)
	}
}
