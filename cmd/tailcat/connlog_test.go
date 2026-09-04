// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// clientIdentity generates a saved client key and returns its path and
// public key string, the form --allow takes.
func clientIdentity(t *testing.T, e *testEnv) (keyPath, pub string) {
	t.Helper()
	keyPath = filepath.Join(t.TempDir(), "c.private.json")
	if out, err := e.cmd("genkey", "--client", "--key="+keyPath).CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}
	out, err := e.cmd("--key="+keyPath, "printpub").Output()
	if err != nil {
		t.Fatalf("printpub: %v", err)
	}
	return keyPath, strings.TrimSpace(string(out))
}

// waitForStderr waits up to 30s for the server's stderr to contain
// want, returning the buffer contents. Connection log lines for a
// closing connection can trail the client's exit.
func waitForStderr(t *testing.T, stderr *bytes.Buffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		got := stderr.String()
		if strings.Contains(got, want) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("server stderr never contained %q:\n%s", want, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServeLogConnections verifies that --log-connections records the
// authenticated client key for the handshake and for each connection,
// along with the port and service reached, without needing --verbose.
func TestServeLogConnections(t *testing.T) {
	e := newTestEnv(t)
	port := startEchoListener(t)
	clientKey, cpub := clientIdentity(t, e)

	_, addr, serverStderr := e.startServer("serve", "--log-connections", strconv.Itoa(int(port)))

	const payload = "logged echo"
	got, err := runClient(t, e.cmd("--key="+clientKey, "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port))), serverStderr, payload)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if got != payload {
		t.Errorf("server echoed %q; want %q", got, payload)
	}

	wantOpen := fmt.Sprintf("[conn] open peer=%v port=%d service=forward via=", cpub, port)
	logs := waitForStderr(t, serverStderr, wantOpen)

	// Which path the via field names depends on whether a direct path
	// has displaced the relay by the time the connection opens, so
	// assert its shape rather than racing that transition.
	viaRe := regexp.MustCompile(regexp.QuoteMeta(wantOpen) + `(direct:\S+|derp:\S*|unknown)`)
	if !viaRe.MatchString(logs) {
		t.Errorf("open line's via field is malformed; want a match for %v:\n%s", viaRe, logs)
	}

	if want := "[peer] allowed key=" + cpub; !strings.Contains(logs, want) {
		t.Errorf("server stderr lacks %q:\n%s", want, logs)
	}
	// The close line carries a duration, so match its shape.
	wantClose := regexp.MustCompile(fmt.Sprintf(`\[conn\] close peer=%v port=%d service=forward duration=\S+`, regexp.QuoteMeta(cpub), port))
	logs = waitForStderr(t, serverStderr, "[conn] close peer="+cpub)
	if !wantClose.MatchString(logs) {
		t.Errorf("server stderr lacks a close line matching %v:\n%s", wantClose, logs)
	}
}

// TestServeLogConnectionsExitNode verifies that connections an exit
// node relays onward are logged with the address they were relayed
// to, which the port-based OnTCP path never sees.
func TestServeLogConnectionsExitNode(t *testing.T) {
	e := newTestEnv(t)
	remotePort := startEchoListener(t)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), remotePort)
	clientKey, cpub := clientIdentity(t, e)

	_, addr, serverStderr := e.startServer("serve", "--log-connections", "exit-node")

	forward := e.cmd("--verbose", "--key="+clientKey, "--derpmap-url="+e.derpMapURL,
		"forward", addr, fmt.Sprintf("0:%s", dst))
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
		forward.Process.Kill()
		forward.Wait()
	})

	// Wait for the local listener the forward advertises on stderr.
	addrRx := regexp.MustCompile(`forwarding (\S+) ->`)
	var local string
	deadline := time.Now().Add(30 * time.Second)
	for local == "" {
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(stderrPath)
			t.Fatalf("forward never listened; stderr:\n%s\nserver stderr:\n%s", b, serverStderr)
		}
		b, _ := os.ReadFile(stderrPath)
		if m := addrRx.FindStringSubmatch(string(b)); m != nil {
			local = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "exit node echo"); err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("[conn] open peer=%v forward=%v via=", cpub, dst)
	waitForStderr(t, serverStderr, want)
}

// TestServeLogConnectionsRefusedPeer verifies that a client the
// --allow list rejects is logged, since a connection log that only
// showed successful clients would hide exactly the events an operator
// turned it on to see.
func TestServeLogConnectionsRefusedPeer(t *testing.T) {
	e := newTestEnv(t)
	port := startEchoListener(t)
	clientKey, cpub := clientIdentity(t, e)
	_, allowedPub := clientIdentity(t, e)

	// Allow a different identity than the one the client uses.
	_, addr, serverStderr := e.startServer("serve", "--log-connections", "--allow="+allowedPub, strconv.Itoa(int(port)))

	// The client can't complete the handshake, so it fails; the
	// server-side refusal is what this test is about.
	client := e.cmd("--key="+clientKey, "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port)))
	client.Stdin = strings.NewReader("denied")
	client.Stdout, client.Stderr = new(bytes.Buffer), new(bytes.Buffer)
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Process.Kill() })

	want := fmt.Sprintf("[peer] refused key=%v reason=not-in-allow", cpub)
	logs := waitForStderr(t, serverStderr, want)
	if strings.Contains(logs, "[conn] open") {
		t.Errorf("refused peer reached a connection:\n%s", logs)
	}
	// The client resends its handshake until it gives up, but a
	// refused key is only reported once.
	if n := strings.Count(logs, want); n != 1 {
		t.Errorf("refusal logged %d times; want 1:\n%s", n, logs)
	}
}

// TestServeWithoutLogConnections verifies the flag is off by default,
// so existing servers' stderr is unchanged.
func TestServeWithoutLogConnections(t *testing.T) {
	e := newTestEnv(t)
	port := startEchoListener(t)
	_, addr, serverStderr := e.startServer("serve", strconv.Itoa(int(port)))

	const payload = "unlogged echo"
	got, err := runClient(t, e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port))), serverStderr, payload)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if got != payload {
		t.Errorf("server echoed %q; want %q", got, payload)
	}
	if logs := serverStderr.String(); strings.Contains(logs, "[conn]") || strings.Contains(logs, "[peer]") {
		t.Errorf("server logged connections without --log-connections:\n%s", logs)
	}
}
