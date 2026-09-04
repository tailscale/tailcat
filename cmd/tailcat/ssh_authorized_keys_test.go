// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tailscale/tailcat"
	gossh "golang.org/x/crypto/ssh"
)

func testAuthorizedKeyLine(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestLoadSSHAuthorizedKeysLiteralAndFile(t *testing.T) {
	literal := testAuthorizedKeyLine(t)
	fileLine := testAuthorizedKeyLine(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte("# from a file\n"+fileLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	texts, err := loadSSHAuthorizedKeys(t.Context(), literal+","+path)
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) != 2 {
		t.Fatalf("loaded %d sources; want 2", len(texts))
	}
	if err := tailcat.ValidateSSHAuthorizedKeys(texts); err != nil {
		t.Fatalf("loaded keys: %v", err)
	}
}

func TestLoadSSHAuthorizedKeysGitHub(t *testing.T) {
	line := testAuthorizedKeyLine(t)
	var gotPath, gotUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUserAgent = r.Header.Get("User-Agent")
		w.Write([]byte(line + "\n"))
	}))
	defer srv.Close()

	texts, err := loadSSHAuthorizedKeysFrom(t.Context(), srv.Client(), srv.URL+"/", "alice@github")
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) != 1 || gotPath != "/alice.keys" || gotUserAgent != "tailcat" {
		t.Errorf("loaded %d sources, path %q, User-Agent %q; want 1, /alice.keys, tailcat", len(texts), gotPath, gotUserAgent)
	}
}

func TestLoadSSHAuthorizedKeysErrors(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed")
	if err := os.WriteFile(malformed, []byte("not a public key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("# no keys\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, sources, want string
	}{
		{"missing file", filepath.Join(dir, "missing"), "reading"},
		{"malformed file", malformed, "line 1"},
		{"empty file", empty, "no SSH public keys"},
		{"malformed literal", "ssh-ed25519 not-base64", "invalid SSH public key"},
		{"empty source", ",", "source 1 is empty"},
		{"invalid GitHub user", "-alice@github", "invalid GitHub username"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadSSHAuthorizedKeys(t.Context(), tt.sources)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadSSHAuthorizedKeys error = %v; want error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadSSHAuthorizedKeysGitHubErrors(t *testing.T) {
	for _, tt := range []struct {
		name       string
		statusCode int
		body, want string
	}{
		{"HTTP error", http.StatusNotFound, "", "404 Not Found"},
		{"malformed response", http.StatusOK, "not a key\n", "line 1"},
		{"empty response", http.StatusOK, "", "no SSH public keys"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			_, err := loadSSHAuthorizedKeysFrom(t.Context(), srv.Client(), srv.URL+"/", "alice@github")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadSSHAuthorizedKeysFrom error = %v; want error containing %q", err, tt.want)
			}
		})
	}
}
