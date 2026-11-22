// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// updateflakes regenerates flakehashes.json, the file that records
// the Nix SRI hash of the Go module vendor tree for flake.nix.
//
// It always runs `go mod vendor` and hashes the result, which takes
// about half a second with a warm module cache. It used to skip that
// when go.mod and go.sum were unchanged, but the vendor tree also
// depends on which packages the module imports: a new import of a
// package from an already-required module changes it without touching
// either file, which left a stale hash that failed the nix build.
// It only rewrites files whose contents change, so repeat runs with no
// input changes are no-ops.
//
// Run from the repo root:
//
//	go run ./tool/updateflakes
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"tailscale.com/cmd/nardump/nardump"
)

const (
	hashesFile      = "flakehashes.json"
	flakeNixFile    = "flake.nix"
	cacheBustPrefix = "# nix-direnv cache busting line:"
)

// FlakeHashes is the on-disk schema of flakehashes.json. It is also
// consumed directly by flake.nix via builtins.fromJSON, so changes
// to the JSON shape must be coordinated with flake.nix.
type FlakeHashes struct {
	Vendor VendorHash `json:"vendor"`
}

// VendorHash records the SRI of `go mod vendor` output.
type VendorHash struct {
	SRI string `json:"sri"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	sri, err := hashVendor()
	if err != nil {
		return err
	}
	if err := writeHashes(FlakeHashes{Vendor: VendorHash{SRI: sri}}); err != nil {
		return err
	}

	// nix-direnv only watches the top-level nix files for changes,
	// so when a referenced hash changes we must also tickle
	// flake.nix to force re-evaluation.
	return updateCacheBust(flakeNixFile, sri)
}

// writeHashes writes h to flakehashes.json, unless the file already
// has exactly those contents.
func writeHashes(h FlakeHashes) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if old, err := os.ReadFile(hashesFile); err == nil && bytes.Equal(old, b) {
		return nil
	}
	return os.WriteFile(hashesFile, b, 0644)
}

func hashVendor() (string, error) {
	out, err := os.MkdirTemp("", "nar-vendor-")
	if err != nil {
		return "", err
	}
	// `go mod vendor -o` requires the destination to not already exist.
	if err := os.Remove(out); err != nil {
		return "", err
	}
	defer os.RemoveAll(out)

	cmd := exec.Command("go", "mod", "vendor", "-o", out)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go mod vendor: %w", err)
	}
	return nardump.SRI(os.DirFS(out))
}

// updateCacheBust rewrites the "# nix-direnv cache busting line"
// in path to embed sri so nix-direnv re-evaluates when the SRI
// changes. The line lives at end of file, so walk in reverse.
func updateCacheBust(path, sri string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	want := []byte(cacheBustPrefix + " " + sri)
	lines := bytes.Split(b, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !bytes.HasPrefix(line, []byte(cacheBustPrefix)) {
			continue
		}
		if bytes.Equal(line, want) {
			return nil
		}
		lines[i] = want
		return os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0644)
	}
	return fmt.Errorf("%s: missing %q line", path, cacheBustPrefix)
}
