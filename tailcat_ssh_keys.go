// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package tailcat

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	ssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
)

// ValidateSSHAuthorizedKeys reports whether texts contains at least one valid
// SSH public key and consists only of blank lines, comments, and public key
// lines in OpenSSH authorized_keys format. Authorized-key options are rejected
// because the built-in server does not implement their restrictions.
func ValidateSSHAuthorizedKeys(texts []string) error {
	_, err := parsedSSHAuthorizedKeys(texts)
	return err
}

func sshPublicKeyHandler(texts []string) (ssh.PublicKeyHandler, error) {
	if texts == nil {
		return nil, nil
	}
	allowed, err := parsedSSHAuthorizedKeys(texts)
	if err != nil {
		return nil, err
	}
	return func(_ ssh.Context, key ssh.PublicKey) error {
		if allowed[string(key.Marshal())] {
			return nil
		}
		return errors.New("SSH public key is not authorized")
	}, nil
}

func parsedSSHAuthorizedKeys(texts []string) (map[string]bool, error) {
	allowed := make(map[string]bool)
	for textIndex, text := range texts {
		for lineIndex, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, options, rest, err := gossh.ParseAuthorizedKey([]byte(line))
			if err != nil || len(bytes.TrimSpace(rest)) != 0 {
				if err == nil {
					err = errors.New("unexpected trailing data")
				}
				return nil, fmt.Errorf("authorized keys entry %d, line %d: %w", textIndex+1, lineIndex+1, err)
			}
			if len(options) != 0 {
				return nil, fmt.Errorf("authorized keys entry %d, line %d: options are not supported", textIndex+1, lineIndex+1)
			}
			allowed[string(key.Marshal())] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no SSH public keys found")
	}
	return allowed, nil
}
