// Package nftables renders GeoIP and datacenter data into nftables .nft map/set files
// and installs them into a running nftables configuration.
package nftables

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

// Input is the data rendered into the .nft files.
type Input struct {
	V4Blocks      []country.Block
	V6Blocks      []country.Block
	Locations     country.Locations
	TrustedAlpha2 map[string]bool // ISO alpha-2 (upper-case) to include in the "interesting" maps
	DatacenterV4  []netip.Prefix
	DatacenterV6  []netip.Prefix
}

// Render writes all .nft files into dir.
func Render(dir string, in Input) error {
	if err := generateDefFiles(dir, in.Locations); err != nil {
		return fmt.Errorf("def files: %w", err)
	}
	if err := generateMapFile(dir, "geoip-ipv4-interesting.nft", "geoip4", "ipv4_addr", in.V4Blocks, in.TrustedAlpha2); err != nil {
		return fmt.Errorf("geoip-ipv4-interesting.nft: %w", err)
	}
	if err := generateMapFile(dir, "geoip-ipv6-interesting.nft", "geoip6", "ipv6_addr", in.V6Blocks, in.TrustedAlpha2); err != nil {
		return fmt.Errorf("geoip-ipv6-interesting.nft: %w", err)
	}
	if err := generateDatacenterSet(dir, "datacenter-ipv4.nft", "datacenter4", "ipv4_addr", in.DatacenterV4); err != nil {
		return fmt.Errorf("datacenter-ipv4.nft: %w", err)
	}
	if err := generateDatacenterSet(dir, "datacenter-ipv6.nft", "datacenter6", "ipv6_addr", in.DatacenterV6); err != nil {
		return fmt.Errorf("datacenter-ipv6.nft: %w", err)
	}
	return nil
}

func generateDefFiles(dir string, locs country.Locations) error {
	// Build per-continent country sets.
	byCont := make(map[string][]country.Info)
	seen := make(map[string]bool) // avoid duplicates by alpha2

	for _, info := range locs {
		if seen[info.Alpha2] {
			continue
		}
		seen[info.Alpha2] = true
		byCont[info.Continent] = append(byCont[info.Continent], info)
	}

	// Sort each continent's list for determinism.
	for cont := range byCont {
		list := byCont[cont]
		sort.Slice(list, func(i, j int) bool { return list[i].Alpha2 < list[j].Alpha2 })
		byCont[cont] = list
	}

	// Write per-continent files.
	continents := []string{"africa", "americas", "antarctica", "asia", "europe", "oceania"}
	for _, cont := range continents {
		var buf bytes.Buffer
		for _, info := range byCont[cont] {
			fmt.Fprintf(&buf, "define %s = %d\n", info.Alpha2, info.Numeric)
		}
		if err := os.WriteFile(filepath.Join(dir, "geoip-def-"+cont+".nft"), buf.Bytes(), 0644); err != nil {
			return err
		}
	}

	// Write geoip-def-all.nft: all countries + continent numerics + continent_code map.
	allInfos := make([]country.Info, 0, len(seen))
	for _, list := range byCont {
		allInfos = append(allInfos, list...)
	}
	sort.Slice(allInfos, func(i, j int) bool { return allInfos[i].Alpha2 < allInfos[j].Alpha2 })

	var buf bytes.Buffer
	for _, info := range allInfos {
		fmt.Fprintf(&buf, "define %s = %d\n", info.Alpha2, info.Numeric)
	}
	buf.WriteString("\n\n")
	buf.WriteString("define africa = 1\n")
	buf.WriteString("define asia = 2\n")
	buf.WriteString("define europe = 3\n")
	buf.WriteString("define americas = 4\n")
	buf.WriteString("define oceania = 5\n")
	buf.WriteString("define antarctica = 6\n")
	buf.WriteString("\n")
	buf.WriteString("map continent_code {\n")
	buf.WriteString("\ttype mark : mark\n")
	buf.WriteString("\tflags interval\n")
	buf.WriteString("\telements = {\n")

	first := true
	for _, info := range allInfos {
		if info.Continent == "" {
			continue
		}
		if !first {
			buf.WriteString(",\n")
		}
		fmt.Fprintf(&buf, "\t\t$%s : $%s", info.Alpha2, info.Continent)
		first = false
	}
	buf.WriteString("\n\t}\n}\n")

	return os.WriteFile(filepath.Join(dir, "geoip-def-all.nft"), buf.Bytes(), 0644)
}

func generateMapFile(dir, filename, mapName, addrType string, blocks []country.Block, filterAlpha2 map[string]bool) error {
	var buf bytes.Buffer
	buf.WriteString("map ")
	buf.WriteString(mapName)
	buf.WriteString(" {\n")
	fmt.Fprintf(&buf, "\ttype %s : mark\n", addrType)
	buf.WriteString("\tflags interval\n")
	buf.WriteString("\telements = {\n")

	first := true
	for _, b := range blocks {
		if filterAlpha2 != nil && !filterAlpha2[b.Alpha2] {
			continue
		}
		if !first {
			buf.WriteString(",\n")
		}
		fmt.Fprintf(&buf, "\t\t%s : $%s", b.Network.String(), b.Alpha2)
		first = false
	}
	buf.WriteString("\n\t}\n}\n")

	return os.WriteFile(filepath.Join(dir, filename), buf.Bytes(), 0644)
}

func generateDatacenterSet(dir, filename, setName, addrType string, prefixes []netip.Prefix) error {
	var buf bytes.Buffer
	buf.WriteString("set ")
	buf.WriteString(setName)
	buf.WriteString(" {\n")
	fmt.Fprintf(&buf, "\ttype %s\n", addrType)
	buf.WriteString("\tflags interval\n")
	buf.WriteString("\telements = {\n")

	for i, pfx := range prefixes {
		if i > 0 {
			buf.WriteString(",\n")
		}
		fmt.Fprintf(&buf, "\t\t%s", pfx.String())
	}
	buf.WriteString("\n\t}\n}\n")

	return os.WriteFile(filepath.Join(dir, filename), buf.Bytes(), 0644)
}
