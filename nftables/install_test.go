package nftables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchIncludePaths(t *testing.T) {
	conf := `table inet geoip {
	include "/etc/nftables/generated/geoip-ipv4-interesting.nft"
	include "/etc/nftables/generated/datacenter-ipv4.nft"
}
`
	got := patchIncludePaths(conf, "/etc/nftables/generated", "/tmp/geoip-xyz")

	if strings.Contains(got, "/etc/nftables/generated/") {
		t.Errorf("production include prefix not rewritten:\n%s", got)
	}
	for _, want := range []string{
		`"/tmp/geoip-xyz/geoip-ipv4-interesting.nft"`,
		`"/tmp/geoip-xyz/datacenter-ipv4.nft"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patched conf missing %q:\n%s", want, got)
		}
	}
}

func TestPatchIncludePaths_TrailingSlashNormalized(t *testing.T) {
	conf := `include "/data/gen/x.nft"`
	// includeDir with a trailing slash and srcDir without one should both normalize.
	got := patchIncludePaths(conf, "/data/gen/", "/tmp/stage")
	if want := `include "/tmp/stage/x.nft"`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCopyNftFiles(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	// Two .nft files plus a non-.nft file that must be ignored.
	files := map[string]string{
		"geoip-ipv4-interesting.nft": "map geoip4 {}\n",
		"datacenter-ipv4.nft":        "set datacenter4 {}\n",
		"README.txt":                 "not nft\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := copyNftFiles(src, dst); err != nil {
		t.Fatalf("copyNftFiles: %v", err)
	}

	// .nft files copied with identical content.
	for _, name := range []string{"geoip-ipv4-interesting.nft", "datacenter-ipv4.nft"} {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("read copied %s: %v", name, err)
		}
		if string(got) != files[name] {
			t.Errorf("%s content = %q, want %q", name, got, files[name])
		}
	}

	// Non-.nft file must not be copied, and no leftover temp files should remain.
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "README.txt" {
			t.Error("README.txt should not have been copied")
		}
		if strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	if len(entries) != 2 {
		t.Errorf("dst has %d entries, want 2", len(entries))
	}
}

func TestCountMapEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.nft")

	// Missing file counts as zero.
	if n, err := CountMapEntries(path); err != nil || n != 0 {
		t.Fatalf("missing file: got (%d, %v), want (0, nil)", n, err)
	}

	content := "\t\t10.0.0.0/8 : $US,\n\t\t2.16.0.0/24 : $DE\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if n, err := CountMapEntries(path); err != nil || n != 2 {
		t.Fatalf("got (%d, %v), want (2, nil)", n, err)
	}
}
