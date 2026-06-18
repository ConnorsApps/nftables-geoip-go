package nftables

import (
	"net/netip"
	"testing"

	"github.com/ConnorsApps/nftables-geoip-go/country"
)

func blocksFromCIDRs(t *testing.T, pairs ...[2]string) []country.Block {
	t.Helper()
	out := make([]country.Block, len(pairs))
	for i, p := range pairs {
		out[i] = country.Block{
			Network: netip.MustParsePrefix(p[0]),
			Alpha2:  p[1],
		}
	}
	return out
}

func TestMergeBlocksAdjacentSameCountry(t *testing.T) {
	blocks := blocksFromCIDRs(t,
		[2]string{"1.0.0.0/24", "US"},
		[2]string{"1.0.1.0/24", "US"},
	)

	got := mergeBlocks(blocks, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.Single() {
		t.Errorf("expected a merged range, got a single CIDR: %+v", r)
	}
	if r.From.String() != "1.0.0.0" || r.To.String() != "1.0.1.255" || r.Alpha2 != "US" {
		t.Errorf("got %+v", r)
	}
}

func TestMergeBlocksNonAdjacentSameCountry(t *testing.T) {
	blocks := blocksFromCIDRs(t,
		[2]string{"1.0.0.0/24", "US"},
		[2]string{"1.0.2.0/24", "US"}, // gap: 1.0.1.0/24 missing
	)

	got := mergeBlocks(blocks, nil)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	for _, r := range got {
		if !r.Single() {
			t.Errorf("expected single-block CIDR, got merged range: %+v", r)
		}
	}
}

func TestMergeBlocksAdjacentDifferentCountry(t *testing.T) {
	blocks := blocksFromCIDRs(t,
		[2]string{"1.0.0.0/24", "US"},
		[2]string{"1.0.1.0/24", "DE"},
	)

	got := mergeBlocks(blocks, nil)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	for _, r := range got {
		if !r.Single() {
			t.Errorf("expected single-block CIDR, got merged range: %+v", r)
		}
	}
}

func TestMergeBlocksIPv6Adjacent(t *testing.T) {
	blocks := blocksFromCIDRs(t,
		[2]string{"2001:db8::/120", "US"},    // 2001:db8::0 - 2001:db8::ff
		[2]string{"2001:db8::100/120", "US"}, // 2001:db8::100 - 2001:db8::1ff
	)

	got := mergeBlocks(blocks, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.Single() {
		t.Errorf("expected a merged range, got a single CIDR: %+v", r)
	}
	if r.From.String() != "2001:db8::" || r.To.String() != "2001:db8::1ff" {
		t.Errorf("got %+v", r)
	}
}

func TestMergeBlocksSingleBlockStaysCIDR(t *testing.T) {
	blocks := blocksFromCIDRs(t, [2]string{"10.0.0.0/8", "US"})

	got := mergeBlocks(blocks, nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	if !got[0].Single() || got[0].CIDR.String() != "10.0.0.0/8" {
		t.Errorf("got %+v", got[0])
	}
}

func TestMergeBlocksUnsortedInput(t *testing.T) {
	sorted := blocksFromCIDRs(t,
		[2]string{"1.0.0.0/24", "US"},
		[2]string{"1.0.1.0/24", "US"},
	)
	unsorted := blocksFromCIDRs(t,
		[2]string{"1.0.1.0/24", "US"},
		[2]string{"1.0.0.0/24", "US"},
	)

	wantGot := mergeBlocks(sorted, nil)
	got := mergeBlocks(unsorted, nil)

	if len(got) != len(wantGot) {
		t.Fatalf("len = %d, want %d", len(got), len(wantGot))
	}
	for i := range got {
		if got[i] != wantGot[i] {
			t.Errorf("element %d: got %+v, want %+v", i, got[i], wantGot[i])
		}
	}
}

func TestMergeBlocksFilter(t *testing.T) {
	blocks := blocksFromCIDRs(t,
		[2]string{"1.0.0.0/24", "US"},
		[2]string{"1.0.1.0/24", "DE"},
	)

	got := mergeBlocks(blocks, trustedSet("US"))
	if len(got) != 1 || got[0].Alpha2 != "US" {
		t.Fatalf("got %+v", got)
	}
}
