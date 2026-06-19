package datacenter

// Mark values for individually-tracked datacenter providers. These live in a range
// (0xda01-0xda0f) distinct from ISO 3166-1 numeric country codes (<1000), the
// continent_code map's continent values (1-6, never set as a live packet mark), and
// the generic blocked-datacenter sentinel BlockedMark (0xdead). New providers can be
// added at the next free value without renumbering existing ones.
const (
	CodeAWS          uint32 = 0xda01
	CodeGCP          uint32 = 0xda02
	CodeDigitalOcean uint32 = 0xda03
	CodeAzure        uint32 = 0xda04

	// BlockedMark is the fallback mark applied to datacenter CIDRs whose provider is
	// not individually allowed through the firewall (see render.go).
	BlockedMark uint32 = 0xdead
)

// codeByProvider maps a Provider.Name() to its mark value. Providers not present here
// (e.g. a caller-supplied custom Provider) get Code 0, which render.go treats as
// "fold into BlockedMark".
var codeByProvider = map[string]uint32{
	"aws":          CodeAWS,
	"gcp":          CodeGCP,
	"digitalocean": CodeDigitalOcean,
	"azure":        CodeAzure,
}

// Codes returns the provider->mark registry. Callers (e.g. the nftables renderer)
// should iterate this in a stable order; sort the returned map's keys for determinism.
func Codes() map[string]uint32 {
	out := make(map[string]uint32, len(codeByProvider))
	for k, v := range codeByProvider {
		out[k] = v
	}
	return out
}
