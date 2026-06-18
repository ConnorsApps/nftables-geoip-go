package nftables

import (
	"net/netip"
	"sort"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

// rangeElem is a contiguous span of addresses attributed to a single country,
// produced by merging one or more adjacent country.Block entries. CIDR is set
// when the span came from exactly one input block, so the renderer can keep
// printing it as a CIDR (matching today's output) instead of an address range.
type rangeElem struct {
	From, To netip.Addr
	Alpha2   string
	CIDR     netip.Prefix // valid only when single block contributed to this range
}

// Single reports whether this range came from exactly one input block.
func (r rangeElem) Single() bool { return r.CIDR.IsValid() }

// CountMergedElements reports how many nft map elements generateMapFile would
// render for blocks after filtering and merging adjacent same-country CIDRs.
// Callers that need to compare a "new" element count against a previous
// generation (e.g. a regression guard) must use this instead of len(blocks),
// since merging changes the element count independently of the block count.
func CountMergedElements(blocks []country.Block, filterAlpha2 map[string]bool) int {
	return len(mergeBlocks(blocks, filterAlpha2))
}

// mergeBlocks filters blocks by filterAlpha2 (nil means no filtering), sorts the
// survivors by address, and coalesces runs of blocks that are both contiguous
// (the next block starts exactly one address after the previous one ends) and
// attributed to the same country into a single rangeElem. This can cut the
// element count of the rendered nft interval map roughly in half, which matters
// because nft's interval-set build cost grows with element count.
func mergeBlocks(blocks []country.Block, filterAlpha2 map[string]bool) []rangeElem {
	filtered := make([]country.Block, 0, len(blocks))
	for _, b := range blocks {
		if filterAlpha2 != nil && !filterAlpha2[b.Alpha2] {
			continue
		}
		filtered = append(filtered, b)
	}
	if len(filtered) == 0 {
		return nil
	}

	sort.Slice(filtered, func(i, j int) bool {
		ai, aj := filtered[i].Network.Addr(), filtered[j].Network.Addr()
		if ai != aj {
			return ai.Less(aj)
		}
		return filtered[i].Network.Bits() < filtered[j].Network.Bits()
	})

	out := make([]rangeElem, 0, len(filtered))
	cur := rangeElem{
		From:   filtered[0].Network.Addr(),
		To:     lastAddr(filtered[0].Network),
		Alpha2: filtered[0].Alpha2,
		CIDR:   filtered[0].Network,
	}

	for _, b := range filtered[1:] {
		from := b.Network.Addr()
		to := lastAddr(b.Network)

		if b.Alpha2 == cur.Alpha2 && cur.To.Next() == from {
			cur.To = to
			cur.CIDR = netip.Prefix{} // no longer a single block, range syntax required
			continue
		}

		out = append(out, cur)
		cur = rangeElem{From: from, To: to, Alpha2: b.Alpha2, CIDR: b.Network}
	}
	out = append(out, cur)

	return out
}

// lastAddr returns the final address covered by prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	raw := addr.AsSlice()
	hostBits := addr.BitLen() - prefix.Bits()

	for i := len(raw) - 1; hostBits > 0; i-- {
		flip := hostBits
		if flip > 8 {
			flip = 8
		}
		raw[i] |= byte(0xFF >> (8 - flip))
		hostBits -= flip
	}

	last, _ := netip.AddrFromSlice(raw)
	if addr.Is4() {
		last = last.Unmap()
	}
	return last
}
