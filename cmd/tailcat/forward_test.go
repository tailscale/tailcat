// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestParseForwardSpec(t *testing.T) {
	for _, tt := range []struct {
		spec, wantAddr string
		wantPort       uint16
		wantTarget     string
		wantErr        bool
	}{
		{"8080", "127.0.0.1:8080", 8080, "", false},
		{"18080:8080", "127.0.0.1:18080", 8080, "", false},
		{"1:65535", "127.0.0.1:1", 65535, "", false},
		{"0", "", 0, "", true},
		{"0:8080", "127.0.0.1:0", 8080, "", false},
		{"13306:192.168.1.10:3306", "127.0.0.1:13306", 0, "192.168.1.10:3306", false},
		{"13306:[2001:db8::10]:3306", "127.0.0.1:13306", 0, "[2001:db8::10]:3306", false},
		{"8080:0", "", 0, "", true},
		{"8080:bad", "", 0, "", true},
		{"8080:192.168.1.10:bad", "", 0, "", true},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := parseForwardSpec("127.0.0.1", tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseForwardSpec succeeded; want error")
				}
				return
			}
			wantTarget := ""
			if got.target.IsValid() {
				wantTarget = got.target.String()
			}
			if err != nil || got.listenAddr != tt.wantAddr || got.port != tt.wantPort || wantTarget != tt.wantTarget {
				t.Fatalf("parseForwardSpec(%q) = %#v, %v; want address %q, port %d, target %q", tt.spec, got, err, tt.wantAddr, tt.wantPort, tt.wantTarget)
			}
		})
	}
}

func TestForwardEndToEnd(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	remotePort := startEchoListener(t)

	_, tailcatAddr, serverStderr := e.startServer("--verbose", "serve", strconv.Itoa(int(remotePort)))
	forward := e.cmd("--verbose", "--key=new", "--derpmap-url="+e.derpMapURL, "forward", tailcatAddr, fmt.Sprintf("0:%d", remotePort))
	stderrPath := filepath.Join(t.TempDir(), "forward.stderr")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	forward.Stderr = stderrFile
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = forward.Process.Kill()
		_ = forward.Wait()
	})
	forwardStderr := func() string {
		b, _ := os.ReadFile(stderrPath)
		return string(b)
	}

	addrRx := regexp.MustCompile(`forwarding (\S+) ->`)
	var addr string
	deadline := time.Now().Add(30 * time.Second)
	for addr == "" {
		if time.Now().After(deadline) {
			t.Fatalf("forward never listened; stderr:\n%s", forwardStderr())
		}
		if m := addrRx.FindStringSubmatch(forwardStderr()); m != nil {
			addr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("forwarding from %s", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const payload = "forwarded over tailcat"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v\nforward stderr:\n%s\nserver stderr:\n%s", err, forwardStderr(), serverStderr)
	}
	if string(got) != payload {
		t.Errorf("got %q; want %q", got, payload)
	}
}

func TestForwardToExitNodeTarget(t *testing.T) {
	skipIfNixSandbox(t) // flaked in the flake sandbox (connection reset mid-tunnel)
	t.Parallel()
	e := newTestEnv(t)
	remotePort := startEchoListener(t)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), remotePort)

	_, tailcatAddr, serverStderr := e.startServer("--verbose", "serve", "exit-node")
	forward := e.cmd("--verbose", "--key=new", "--derpmap-url="+e.derpMapURL, "forward", tailcatAddr, fmt.Sprintf("0:%s", dst))
	stderrPath := filepath.Join(t.TempDir(), "forward-exit-node.stderr")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	forward.Stderr = stderrFile
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = forward.Process.Kill()
		_ = forward.Wait()
	})
	forwardStderr := func() string {
		b, _ := os.ReadFile(stderrPath)
		return string(b)
	}

	addrRx := regexp.MustCompile(`forwarding (\S+) ->`)
	var addr string
	deadline := time.Now().Add(30 * time.Second)
	for addr == "" {
		if time.Now().After(deadline) {
			t.Fatalf("forward never listened; stderr:\n%s\nserver stderr:\n%s", forwardStderr(), serverStderr)
		}
		if m := addrRx.FindStringSubmatch(forwardStderr()); m != nil {
			addr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const payload = "forwarded to an exit-node target"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v\nforward stderr:\n%s\nserver stderr:\n%s", err, forwardStderr(), serverStderr)
	}
	if string(got) != payload {
		t.Errorf("got %q; want %q", got, payload)
	}
}
