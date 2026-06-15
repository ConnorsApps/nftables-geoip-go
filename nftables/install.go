package nftables

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SpanHook starts a named span and returns an end function; see geoip.SpanHook.
type SpanHook = func(ctx context.Context, name string) (context.Context, func(error))

func callSpan(ctx context.Context, h SpanHook, name string) (context.Context, func(error)) {
	if h == nil {
		return ctx, func(error) {}
	}
	return h(ctx, name)
}

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
	// StartSpan is optional; when set, spans are recorded for validate, copy, and reload.
	StartSpan SpanHook
}

// Install validates the freshly generated files in srcDir against the live nftables
// config, then copies them into cfg.OutputDir and runs the reload command. When
// SkipValidate is true it only copies the files.
func Install(ctx context.Context, srcDir string, cfg InstallConfig) error {
	destDir := cfg.OutputDir
	if cfg.SkipValidate {
		_, end := callSpan(ctx, cfg.StartSpan, "nftables.copy")
		err := copyNftFiles(srcDir, destDir)
		end(err)
		return err
	}

	includeDir := cfg.IncludeDir
	if includeDir == "" {
		includeDir = cfg.OutputDir
	}

	confBytes, err := os.ReadFile(cfg.NFTablesConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfg.NFTablesConfPath, err)
	}

	patched := patchIncludePaths(string(confBytes), includeDir, srcDir)

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

	_, endValidate := callSpan(ctx, cfg.StartSpan, "nftables.validate")
	out, err := exec.CommandContext(ctx, "nft", "-c", "-f", tmpConf.Name()).CombinedOutput()
	endValidate(err)
	if err != nil {
		return fmt.Errorf("nft -c -f validation failed: %w\n%s", err, out)
	}

	_, endCopy := callSpan(ctx, cfg.StartSpan, "nftables.copy")
	err = copyNftFiles(srcDir, destDir)
	endCopy(err)
	if err != nil {
		return err
	}

	if len(cfg.ReloadCommand) > 0 {
		_, endReload := callSpan(ctx, cfg.StartSpan, "nftables.reload")
		cmd := exec.CommandContext(ctx, cfg.ReloadCommand[0], cfg.ReloadCommand[1:]...)
		out, err := cmd.CombinedOutput()
		endReload(err)
		if err != nil {
			return fmt.Errorf("reload command %v: %w\n%s", cfg.ReloadCommand, err, out)
		}
	}
	return nil
}

// patchIncludePaths rewrites the production include directory in an nftables config to
// point at srcDir, so the freshly generated files are validated in place. The directory
// is normalized to a trailing slash so the replacement targets the directory prefix
// exactly rather than any path that merely starts with includeDir.
func patchIncludePaths(conf, includeDir, srcDir string) string {
	includePrefix := strings.TrimRight(includeDir, "/") + "/"
	return strings.ReplaceAll(conf, includePrefix, strings.TrimRight(srcDir, "/")+"/")
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
