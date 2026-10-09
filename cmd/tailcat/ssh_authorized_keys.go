// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
)

const maxSSHAuthorizedKeysSize = 1 << 20

var githubUsernameRx = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

// loadSSHAuthorizedKeys resolves a comma-separated list of authorized-key
// sources. A source is a literal public key line, a path to an authorized_keys
// file, or a GitHub account written "user@github".
func loadSSHAuthorizedKeys(ctx context.Context, sourceList string) ([]string, error) {
	return loadSSHAuthorizedKeysFrom(ctx, http.DefaultClient, "https://github.com/", sourceList)
}

func loadSSHAuthorizedKeysFrom(ctx context.Context, client *http.Client, githubBaseURL, sourceList string) ([]string, error) {
	var texts []string
	for sourceIndex, source := range strings.Split(sourceList, ",") {
		source = strings.TrimSpace(source)
		if source == "" {
			return nil, fmt.Errorf("source %d is empty", sourceIndex+1)
		}

		var (
			text []byte
			err  error
		)
		if user, ok := strings.CutSuffix(source, "@github"); ok {
			if !githubUsernameRx.MatchString(user) {
				return nil, fmt.Errorf("source %d: invalid GitHub username %q", sourceIndex+1, user)
			}
			text, err = fetchGitHubSSHKeys(ctx, client, githubBaseURL, user)
			if err != nil {
				return nil, fmt.Errorf("source %d (%s): %w", sourceIndex+1, source, err)
			}
		} else if fileText, fileErr := readSSHAuthorizedKeysFile(source); fileErr == nil {
			text = fileText
		} else if validationErr := tailcat.ValidateSSHAuthorizedKeys([]string{source}); validationErr == nil {
			text = []byte(source)
		} else if looksLikeSSHPublicKey(source) {
			return nil, fmt.Errorf("source %d: invalid SSH public key: %w", sourceIndex+1, validationErr)
		} else {
			return nil, fmt.Errorf("source %d: reading %q: %w", sourceIndex+1, source, fileErr)
		}

		if err := tailcat.ValidateSSHAuthorizedKeys([]string{string(text)}); err != nil {
			return nil, fmt.Errorf("source %d (%s): %w", sourceIndex+1, source, err)
		}
		texts = append(texts, string(text))
	}
	if err := tailcat.ValidateSSHAuthorizedKeys(texts); err != nil {
		return nil, err
	}
	return texts, nil
}

func looksLikeSSHPublicKey(source string) bool {
	fields := strings.Fields(source)
	if len(fields) == 0 {
		return false
	}
	first := fields[0]
	return strings.HasPrefix(first, "ssh-") ||
		strings.HasPrefix(first, "ecdsa-") ||
		strings.HasPrefix(first, "sk-")
}

func readSSHAuthorizedKeysFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSSHAuthorizedKeysSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSSHAuthorizedKeysSize {
		return nil, fmt.Errorf("file is larger than %d bytes", maxSSHAuthorizedKeysSize)
	}
	return b, nil
}

func fetchGitHubSSHKeys(ctx context.Context, client *http.Client, baseURL, user string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+url.PathEscape(user)+".keys", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tailcat")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching GitHub keys: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching GitHub keys: %s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxSSHAuthorizedKeysSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading GitHub keys: %w", err)
	}
	if len(b) > maxSSHAuthorizedKeysSize {
		return nil, fmt.Errorf("GitHub key list is larger than %d bytes", maxSSHAuthorizedKeysSize)
	}
	return b, nil
}
