// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package tailcat

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func testSSHSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSSHPublicKeyHandler(t *testing.T) {
	allowed := testSSHSigner(t)
	other := testSSHSigner(t)
	text := "# trusted key\n" + string(gossh.MarshalAuthorizedKey(allowed.PublicKey()))
	h, err := sshPublicKeyHandler([]string{text})
	if err != nil {
		t.Fatal(err)
	}
	if err := h(nil, allowed.PublicKey()); err != nil {
		t.Errorf("allowed key rejected: %v", err)
	}
	if err := h(nil, other.PublicKey()); err == nil {
		t.Error("unlisted key accepted")
	}

	h, err = sshPublicKeyHandler(nil)
	if err != nil || h != nil {
		t.Errorf("nil authorized keys = (%v, %v); want (nil, nil)", h, err)
	}
	if h, err := sshPublicKeyHandler([]string{}); err == nil || h != nil {
		t.Errorf("non-nil empty authorized keys = (%v, %v); want (nil, error)", h, err)
	}
}

func TestValidateSSHAuthorizedKeys(t *testing.T) {
	line := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(testSSHSigner(t).PublicKey())))
	for _, tt := range []struct {
		name    string
		texts   []string
		wantErr string
	}{
		{"one key", []string{line}, ""},
		{"multiple entries", []string{"# comment only", line, "\n" + line + "\n"}, ""},
		{"no keys", []string{"\n# only a comment\n"}, "no SSH public keys"},
		{"malformed", []string{"ssh-ed25519 not-base64"}, "line 1"},
		{"options", []string{`command="echo no" ` + line}, "options are not supported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHAuthorizedKeys(tt.texts)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("ValidateSSHAuthorizedKeys: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("ValidateSSHAuthorizedKeys error = %v; want error containing %q", err, tt.wantErr)
			}
		})
	}
}
