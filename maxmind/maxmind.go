// Package maxmind downloads and parses the MaxMind GeoLite2 Country CSV bundle into
// country-attributed CIDR blocks. The HTTP download and the ZIP parsing are split so
// the parser can be unit-tested with an in-memory bundle and no network access.
package maxmind

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

const urlTemplate = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=zip"

// Result holds the parsed GeoLite2 Country data.
type Result struct {
	V4        []country.Block
	V6        []country.Block
	Locations country.Locations
}

// Fetch downloads the GeoLite2 Country CSV bundle with the given client and license
// key, then parses it. The client is supplied by the caller so transports (e.g. an
// instrumented one) can be injected.
func Fetch(ctx context.Context, client *http.Client, licenseKey string) (Result, error) {
	url := fmt.Sprintf(urlTemplate, licenseKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, fmt.Errorf("build maxmind request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("download maxmind: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("maxmind download returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, fmt.Errorf("read maxmind body: %w", err)
	}

	return Parse(body)
}

// Parse parses the GeoLite2 Country CSV ZIP bundle from raw bytes. Split out from
// Fetch so it can be unit-tested with an in-memory zip.
func Parse(body []byte) (Result, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return Result{}, fmt.Errorf("open maxmind zip: %w", err)
	}

	files := make(map[string]*zip.File)
	for _, f := range zr.File {
		// zip entry names include a directory prefix like GeoLite2-Country-CSV_20240101/
		files[path.Base(f.Name)] = f
	}

	locs, err := parseLocations(files["GeoLite2-Country-Locations-en.csv"])
	if err != nil {
		return Result{}, fmt.Errorf("parse locations: %w", err)
	}

	v4, err := parseBlocks(files["GeoLite2-Country-Blocks-IPv4.csv"], locs)
	if err != nil {
		return Result{}, fmt.Errorf("parse IPv4 blocks: %w", err)
	}

	v6, err := parseBlocks(files["GeoLite2-Country-Blocks-IPv6.csv"], locs)
	if err != nil {
		return Result{}, fmt.Errorf("parse IPv6 blocks: %w", err)
	}

	return Result{V4: v4, V6: v6, Locations: locs}, nil
}

func parseLocations(f *zip.File) (country.Locations, error) {
	if f == nil {
		return nil, fmt.Errorf("GeoLite2-Country-Locations-en.csv not found in zip")
	}

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	r := csv.NewReader(rc)
	// skip header
	if _, err := r.Read(); err != nil {
		return nil, err
	}

	locs := make(country.Locations)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// columns: geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
		if len(row) < 5 {
			continue
		}
		geonameID := row[0]
		continentCode := row[2]
		alpha2 := row[4]
		if alpha2 == "" {
			continue // continent-level entry, skip
		}
		numeric, ok := isoNumericByAlpha2[alpha2]
		if !ok {
			continue
		}
		continent := continentNameByMaxMindCode[continentCode]
		if continent == "" {
			continue
		}
		locs[geonameID] = country.Info{
			Alpha2:    alpha2,
			Numeric:   numeric,
			Continent: continent,
		}
	}
	return locs, nil
}

func parseBlocks(f *zip.File, locs country.Locations) ([]country.Block, error) {
	if f == nil {
		return nil, fmt.Errorf("blocks CSV file not found in zip")
	}

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	r := csv.NewReader(rc)
	// skip header
	if _, err := r.Read(); err != nil {
		return nil, err
	}

	var blocks []country.Block
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// columns: network,geoname_id,registered_country_geoname_id,...
		if len(row) < 3 {
			continue
		}
		cidr := row[0]
		geonameID := row[1]
		if geonameID == "" {
			geonameID = row[2] // fall back to registered_country_geoname_id
		}
		if geonameID == "" {
			continue
		}

		info, ok := locs[geonameID]
		if !ok {
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}

		blocks = append(blocks, country.Block{
			Network: prefix.Masked(),
			Alpha2:  info.Alpha2,
			Numeric: info.Numeric,
		})
	}
	return blocks, nil
}
