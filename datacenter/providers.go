package datacenter

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
)

const (
	awsURL            = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	gcpURL            = "https://www.gstatic.com/ipranges/cloud.json"
	doURL             = "https://www.digitalocean.com/geo/google.csv"
	azureDownloadPage = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
)

var azureURLRe = regexp.MustCompile(`https://download\.microsoft\.com/[^"']+ServiceTags_Public_\d+\.json`)

// AWS fetches datacenter ranges from the AWS ip-ranges.json feed.
type AWS struct{}

func (AWS) Name() string { return "aws" }

func (AWS) Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error) {
	body, err := fetchBytes(ctx, client, awsURL)
	if err != nil {
		return nil, nil, err
	}
	return parseAWS(body)
}

// parseAWS parses the AWS ip-ranges.json payload into IPv4/IPv6 prefixes.
func parseAWS(body []byte) (v4, v6 []netip.Prefix, err error) {
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
			v4 = append(v4, pfx.Masked())
		}
	}
	for _, p := range payload.IPv6Prefixes {
		if pfx, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
			v6 = append(v6, pfx.Masked())
		}
	}
	return v4, v6, nil
}

// GCP fetches datacenter ranges from the GCP cloud.json feed.
type GCP struct{}

func (GCP) Name() string { return "gcp" }

func (GCP) Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error) {
	body, err := fetchBytes(ctx, client, gcpURL)
	if err != nil {
		return nil, nil, err
	}
	return parseGCP(body)
}

// parseGCP parses the GCP cloud.json payload into IPv4/IPv6 prefixes.
func parseGCP(body []byte) (v4, v6 []netip.Prefix, err error) {
	var payload struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, err
	}
	for _, p := range payload.Prefixes {
		if p.IPv4Prefix != "" {
			if pfx, err := netip.ParsePrefix(p.IPv4Prefix); err == nil {
				v4 = append(v4, pfx.Masked())
			}
		}
		if p.IPv6Prefix != "" {
			if pfx, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
				v6 = append(v6, pfx.Masked())
			}
		}
	}
	return v4, v6, nil
}

// DigitalOcean fetches datacenter ranges from the DigitalOcean geo CSV feed.
type DigitalOcean struct{}

func (DigitalOcean) Name() string { return "digitalocean" }

func (DigitalOcean) Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error) {
	body, err := fetchBytes(ctx, client, doURL)
	if err != nil {
		return nil, nil, err
	}
	return parseDigitalOceanCSV(body)
}

// parseDigitalOceanCSV parses the DigitalOcean geo CSV (first column is the CIDR).
func parseDigitalOceanCSV(body []byte) (v4, v6 []netip.Prefix, err error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(row) == 0 {
			continue
		}
		pfx, err := netip.ParsePrefix(row[0])
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		if pfx.Addr().Is4() {
			v4 = append(v4, pfx)
		} else {
			v6 = append(v6, pfx)
		}
	}
	return v4, v6, nil
}

// Azure fetches datacenter ranges from the Azure ServiceTags feed. Azure does not
// publish a stable JSON URL, so the dated ServiceTags file is scraped from the
// download page — the most brittle source, but its failure is isolated.
type Azure struct{}

func (Azure) Name() string { return "azure" }

func (Azure) Fetch(ctx context.Context, client *http.Client) (v4, v6 []netip.Prefix, err error) {
	pageBody, err := fetchBytes(ctx, client, azureDownloadPage)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch azure download page: %w", err)
	}

	match := azureURLRe.Find(pageBody)
	if match == nil {
		return nil, nil, fmt.Errorf("azure ServiceTags URL not found on download page")
	}

	body, err := fetchBytes(ctx, client, string(match))
	if err != nil {
		return nil, nil, fmt.Errorf("fetch azure service tags: %w", err)
	}
	return parseAzureServiceTags(body)
}

// parseAzureServiceTags parses the Azure ServiceTags_Public JSON into prefixes.
func parseAzureServiceTags(body []byte) (v4, v6 []netip.Prefix, err error) {
	var payload struct {
		Values []struct {
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, err
	}

	for _, v := range payload.Values {
		for _, cidr := range v.Properties.AddressPrefixes {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			pfx = pfx.Masked()
			if pfx.Addr().Is4() {
				v4 = append(v4, pfx)
			} else {
				v6 = append(v6, pfx)
			}
		}
	}
	return v4, v6, nil
}

func fetchBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// AggregatePrefixes sorts and removes covered prefixes from a list.
func AggregatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})

	result := []netip.Prefix{prefixes[0]}
	for _, p := range prefixes[1:] {
		last := result[len(result)-1]
		// Skip if p is an exact duplicate or covered by last.
		if last.Contains(p.Addr()) && p.Bits() >= last.Bits() {
			continue
		}
		result = append(result, p)
	}
	return result
}
