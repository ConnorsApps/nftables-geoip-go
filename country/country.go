// Package country holds the shared GeoIP domain types: the country-attributed CIDR
// blocks and country metadata produced by the maxmind package and consumed when
// rendering nftables files. It carries data only, with no behavior or dependencies
// beyond the standard library.
package country

import "net/netip"

// Block is a single CIDR network attributed to a country.
type Block struct {
	Network netip.Prefix
	Alpha2  string // ISO 3166-1 alpha-2, e.g. "US"
	Numeric uint32 // ISO 3166-1 numeric (the nft mark value), e.g. 840
}

// Info describes a country: its ISO codes and the continent it belongs to.
type Info struct {
	Alpha2    string
	Numeric   uint32
	Continent string // "africa", "asia", "europe", "americas", "oceania", "antarctica"
}

// Locations maps a MaxMind geoname_id to country Info.
type Locations map[string]Info
