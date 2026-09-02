// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ssh

package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tailscale/tailcat"
)

func TestSSHRejectsInvalidAddr(t *testing.T) {
	for _, tt := range []struct {
		name    string
		addr    string
		wantErr string
	}{
		{"missing prefix", "not-an-address", `doesn't start with "tc"`},
		{"invalid base64", "tc%", "base64 decode"},
		{"invalid CBOR", "tc" + base64.RawURLEncoding.EncodeToString([]byte("not CBOR")), "CBOR unmarshal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := clientSSHMode("22", []string{tt.addr})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("clientSSHMode(%q) error = %v; want an error containing %q", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestSSHProxyCommandDERPMap(t *testing.T) {
	const (
		exe  = "/path/to/tailcat"
		key  = "client-default"
		addr = "tc-short-addr"
		port = "22"
		url  = "https://derp.example.com/derpmap.json"
	)
	got, err := sshProxyCommand(exe, proxyOpts{keyName: key, derpMapURL: url}, addr, port)
	if err != nil {
		t.Fatal(err)
	}
	want := `'` + exe + `' '--key=client-default' '--derpmap-url=https://derp.example.com/derpmap.json' 'tc-short-addr' '22'`
	if runtime.GOOS == "windows" {
		want = `"/path/to/tailcat" "--key=client-default" "--derpmap-url=https://derp.example.com/derpmap.json" "tc-short-addr" "22"`
	}
	if got != want {
		t.Errorf("sshProxyCommand with custom DERP map = %q; want %q", got, want)
	}

	got, err = sshProxyCommand(exe, proxyOpts{keyName: key, derpMapURL: tailcat.DefaultDERPMapURL}, addr, port)
	if err != nil {
		t.Fatal(err)
	}
	want = `'` + exe + `' '--key=client-default' 'tc-short-addr' '22'`
	if runtime.GOOS == "windows" {
		want = `"/path/to/tailcat" "--key=client-default" "tc-short-addr" "22"`
	}
	if got != want {
		t.Errorf("sshProxyCommand with default DERP map = %q; want %q", got, want)
	}

	// No --key flag at all when unset. The shell would collapse
	// --key="" to --key=, which ff parses by consuming the next
	// argument, the tailcat address.
	got, err = sshProxyCommand(exe, proxyOpts{derpMapURL: tailcat.DefaultDERPMapURL}, addr, port)
	if err != nil {
		t.Fatal(err)
	}
	want = `'` + exe + `' 'tc-short-addr' '22'`
	if runtime.GOOS == "windows" {
		want = `"/path/to/tailcat" "tc-short-addr" "22"`
	}
	if got != want {
		t.Errorf("sshProxyCommand with no key = %q; want %q", got, want)
	}

	// --auto-region has to reach the child: it, not the ssh process,
	// is what connects.
	got, err = sshProxyCommand(exe, proxyOpts{derpMapURL: tailcat.DefaultDERPMapURL, autoRegion: true}, addr, port)
	if err != nil {
		t.Fatal(err)
	}
	want = `'` + exe + `' '--auto-region' 'tc-short-addr' '22'`
	if runtime.GOOS == "windows" {
		want = `"/path/to/tailcat" "--auto-region" "tc-short-addr" "22"`
	}
	if got != want {
		t.Errorf("sshProxyCommand with auto-region = %q; want %q", got, want)
	}
}

func TestProxyCommandJoinUnix(t *testing.T) {
	tmpDir := t.TempDir()
	injected := filepath.Join(tmpDir, "injected")
	program := filepath.Join(tmpDir, "print args; false")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	key := `key $(touch ` + injected + `) ' " $HOME`
	url := "https://example.invalid/`touch " + injected + "`?x=%h&y=two words"

	command, err := proxyCommandJoinUnix([]string{program, "--key=" + key, "--derpmap-url=" + url, "tc-safe", "22"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate OpenSSH's documented %% -> % expansion before it invokes the
	// shell. The shell must then see every dynamic value as one literal arg.
	command = strings.ReplaceAll(command, "%%", "%")
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		t.Fatalf("running ProxyCommand: %v", err)
	}
	want := "<--key=" + key + ">\n<--derpmap-url=" + url + ">\n<tc-safe>\n<22>\n"
	if string(out) != want {
		t.Fatalf("ProxyCommand output = %q; want %q", out, want)
	}
	if _, err := os.Stat(injected); !os.IsNotExist(err) {
		t.Fatalf("shell command substitution ran; Stat(%q) error = %v", injected, err)
	}
	if _, err := proxyCommandJoinUnix([]string{"line\nbreak"}); err == nil {
		t.Fatal("proxyCommandJoinUnix accepted a newline")
	}
}

func TestProxyCommandJoinWindows(t *testing.T) {
	got, err := proxyCommandJoinWindows([]string{`C:\Program Files\tailcat.exe`, `--key=a&b`, `tc-safe`, `22`})
	if err != nil {
		t.Fatal(err)
	}
	want := `"C:\Program Files\tailcat.exe" "--key=a&b" "tc-safe" "22"`
	if got != want {
		t.Fatalf("proxyCommandJoinWindows = %q; want %q", got, want)
	}
	if got := quoteWindowsCommandArg(`C:\tailcat\`); got != `"C:\tailcat\\"` {
		t.Errorf("quoteWindowsCommandArg with trailing slash = %q", got)
	}
	for _, arg := range []string{`has"quote`, "has%percent", "has!bang", "has\nnewline", "has\x00nul"} {
		if _, err := proxyCommandJoinWindows([]string{arg}); err == nil {
			t.Errorf("proxyCommandJoinWindows accepted unsafe argument %q", arg)
		}
	}
}

func TestValidatedSSHPort(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		valid    bool
	}{
		{"22", "22", true},
		{"0022", "22", true},
		{"192.0.2.1", "192.0.2.1:22", true},
		{"192.0.2.1:2222", "192.0.2.1:2222", true},
		{"2001:db8::1", "[2001:db8::1]:22", true},
		{"[2001:db8::1]:2222", "[2001:db8::1]:2222", true},
		{"", "", false},
		{"0", "", false},
		{"65536", "", false},
		{"22; touch /tmp/injected", "", false},
		{"example.com:22", "", false},
	} {
		got, err := validatedSSHPort(tt.in)
		if (err == nil) != tt.valid || got != tt.want {
			t.Errorf("validatedSSHPort(%q) = %q, %v; want %q, valid=%v", tt.in, got, err, tt.want, tt.valid)
		}
	}
}

func TestSSHDestHost(t *testing.T) {
	// A realistic Addr, taken from an existing test fixture elsewhere
	// in this package.
	const addr = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"

	got := sshDestHost(addr)
	if !strings.HasPrefix(got, "tailcat-") {
		t.Fatalf("sshDestHost(%q) = %q; want tailcat- prefix", addr, got)
	}
	if len(got) > 24 {
		t.Fatalf("sshDestHost(%q) = %q (%d bytes); want a short, fixed-width host", addr, got, len(got))
	}

	// Deterministic: same addr always produces the same host, so ssh's own
	// connection sharing (keyed off ControlPath, hence off this string)
	// keeps reusing the right control socket across invocations.
	if again := sshDestHost(addr); again != got {
		t.Fatalf("sshDestHost(%q) is not deterministic: %q != %q", addr, got, again)
	}

	// Distinct addrs must not collide, or ssh would multiplex two different
	// tailcat servers onto the same control socket.
	const otherAddr = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGF2"
	if other := sshDestHost(otherAddr); other == got {
		t.Fatalf("sshDestHost collided for distinct addrs: %q", got)
	}

	// The whole point: it must actually fit an AF_UNIX ControlPath, unlike
	// a long Addr used directly. Linux's sun_path is 108 bytes,
	// including the trailing NUL; macOS's is 104. Give plenty of headroom
	// for a real home directory and username.
	const controlPath = "/home/someuser/.ssh/master-someuser@" + "PLACEHOLDER" + ":22"
	if got := len(strings.Replace(controlPath, "PLACEHOLDER", sshDestHost(addr), 1)); got >= 100 {
		t.Fatalf("example ControlPath is %d bytes; want comfortably under the ~104-108 byte AF_UNIX limit", got)
	}
}
