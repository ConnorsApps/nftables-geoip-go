package nftables

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallConfig controls how generated files are validated and installed.
type InstallConfig struct {
	// OutputDir is where the .nft files are copied (the live include directory).
	OutputDir string
	// NFTablesConfPath is the system nftables config used for the `nft -c` check.
	NFTablesConfPath string
	// IncludeDir is the include prefix in NFTablesConfPath that is rewritten to the
	// staging directory during validation. Defaults to OutputDir when empty.
	IncludeDir string
	// ReloadCommand is run after a successful copy. Skipped when empty.
	ReloadCommand []string
	// SkipValidate skips the `nft -c` check and reload (for machines without nftables).
	SkipValidate bool
}

// Install validates the freshly generated files in srcDir against the live nftables
// config, then copies them into cfg.OutputDir and runs the reload command. When
// SkipValidate is true it only copies the files.
func Install(srcDir string, cfg InstallConfig) error {
	destDir := cfg.OutputDir
	if cfg.SkipValidate {
		return copyNftFiles(srcDir, destDir)
	}

	includeDir := cfg.IncludeDir
	if includeDir == "" {
		includeDir = cfg.OutputDir
	}

	confBytes, err := os.ReadFile(cfg.NFTablesConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfg.NFTablesConfPath, err)
	}

	// Rewrite the production include directory to point at srcDir so the freshly
	// generated files are validated in place. Normalize to a trailing slash so the
	// replacement targets the directory prefix exactly.
	includePrefix := strings.TrimRight(includeDir, "/") + "/"
	patched := strings.ReplaceAll(string(confBytes), includePrefix, srcDir+"/")

	tmpConf, err := os.CreateTemp("", "nftables-check-*.conf")
	if err != nil {
		return fmt.Errorf("create temp conf: %w", err)
	}
	defer os.Remove(tmpConf.Name())

	if _, err := io.WriteString(tmpConf, patched); err != nil {
		tmpConf.Close()
		return fmt.Errorf("write temp conf: %w", err)
	}
	tmpConf.Close()

	if out, err := exec.Command("nft", "-c", "-f", tmpConf.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("nft -c -f validation failed: %w\n%s", err, out)
	}

	if err := copyNftFiles(srcDir, destDir); err != nil {
		return err
	}

	if len(cfg.ReloadCommand) > 0 {
		cmd := exec.Command(cfg.ReloadCommand[0], cfg.ReloadCommand[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("reload command %v: %w\n%s", cfg.ReloadCommand, err, out)
		}
	}
	return nil
}

func copyNftFiles(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".nft") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		// Write to a temp file in the destination directory then rename, so a reader
		// (e.g. an nft reload) never observes a half-written file. Rename is atomic
		// within the same filesystem.
		final := filepath.Join(dst, e.Name())
		tmp := filepath.Join(dst, "."+e.Name()+".tmp")
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			return err
		}
		if err := os.Rename(tmp, final); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// CountMapEntries counts the number of map entries (lines containing " : $") in a file.
// A missing file counts as zero.
func CountMapEntries(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return bytes.Count(data, []byte(" : $")), nil
}
