// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

// startEchoListener starts a TCP echo server on a 127.0.0.1 ephemeral
// port, closed with the test, and returns its port.
func startEchoListener(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func TestServeWithoutPSK(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	port := startEchoListener(t)
	_, addr, serverStderr := e.startServer("serve", "--psk=false", strconv.Itoa(int(port)))

	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatal(err)
	}
	if !ci.PresharedKey.IsZero() {
		t.Fatal("serve --psk=false produced an address containing a PSK")
	}
	waitForLog(t, serverStderr, "# ⚠️ WARNING: serving without a WireGuard PSK\n")

	const payload = "echo without a pre-shared key"
	got, err := runClient(t, e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port))), serverStderr, payload)
	if err != nil {
		t.Fatalf("client to server without PSK: %v", err)
	}
	if got != payload {
		t.Errorf("server echoed %q; want %q", got, payload)
	}
}

func TestServeRemembersSavedKeyWithoutPSK(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	port := startEchoListener(t)
	keyFile := filepath.Join(t.TempDir(), "server.private.json")
	genkey := e.cmd("genkey", "--key="+keyFile, "--region=1", "--psk=false")
	if out, err := genkey.CombinedOutput(); err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}

	addrFile := filepath.Join(t.TempDir(), "addr")
	server := e.cmd("--key="+keyFile, "--derpmap-url="+e.derpMapURL, "serve", strconv.Itoa(int(port)))
	server.Env = append(server.Env, "TAILCAT_ADDR_FILE="+addrFile)
	var serverStderr lockedBuf
	server.Stderr = &serverStderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Process.Kill() })
	addr := waitAddr(t, addrFile, &serverStderr)

	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatal(err)
	}
	if !ci.PresharedKey.IsZero() {
		t.Fatal("saved PSK-free key produced an address containing a PSK")
	}
	waitForLog(t, &serverStderr, fmt.Sprintf("# ⚠️ WARNING: saved key %q is not using a WireGuard PSK\n", keyFile))

	const payload = "echo with saved PSK policy"
	got, err := runClient(t, e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port))), &serverStderr, payload)
	if err != nil {
		t.Fatalf("client to saved server without PSK: %v", err)
	}
	if got != payload {
		t.Errorf("server echoed %q; want %q", got, payload)
	}
}

// runClient runs an unstarted tailcat client command with payload on
// its stdin and a 60 second watchdog, returning its stdout and error.
// The watchdog only exists to catch true hangs; it's generous because
// a loaded machine can drop relayed packets and leave the transfer
// waiting out TCP retransmit backoff. On failure, the error includes
// the client's stderr and the given server stderr (which may be nil),
// so both sides of a wedged conversation are visible.
func runClient(t *testing.T, client *exec.Cmd, serverStderr *lockedBuf, payload string) (string, error) {
	t.Helper()
	client.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	client.Stdout = &stdout
	client.Stderr = &stderr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	bothStderrs := func() string {
		s := fmt.Sprintf("client stderr:\n%s", stderr.String())
		if serverStderr != nil {
			s += fmt.Sprintf("\nserver stderr:\n%s", serverStderr.String())
		}
		return s
	}
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			err = fmt.Errorf("%w\n%s", err, bothStderrs())
		}
		return stdout.String(), err
	case <-time.After(60 * time.Second):
		client.Process.Kill()
		t.Fatalf("client did not exit within 60s\n%s", bothStderrs())
		panic("unreachable")
	}
}

// TestServePorts verifies that a server with an explicit port list
// (given to the serve subcommand) proxies connections on a served
// port to the same local port, and refuses connections to ports
// outside the list.
func TestServePorts(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	port := startEchoListener(t)

	// Grab a second port that's free but not served.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unservedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	_, addr, serverStderr := e.startServer("--verbose", "serve", strconv.Itoa(int(port)))

	const payload = "echo through a served port"
	got, err := runClient(t, e.cmd("--verbose", "--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(int(port))), serverStderr, payload)
	if err != nil {
		t.Fatalf("client to served port: %v", err)
	}
	if got != payload {
		t.Errorf("served port echoed %q; want %q", got, payload)
	}

	// The packet filter silently drops SYNs to unserved ports (no
	// RST; see Server.ServedTCPPorts), so instead of waiting out the
	// client's whole dial timeout, watch the verbose server's filter
	// log for the drop and then check the client never got the echo.
	client := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(unservedPort))
	client.Stdin = strings.NewReader(payload)
	var clientOut bytes.Buffer
	client.Stdout = &clientOut
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	dropRx := regexp.MustCompile(fmt.Sprintf(`Drop: TCP\{.*\]:%d\}`, unservedPort))
	deadline := time.Now().Add(30 * time.Second)
	for !dropRx.MatchString(serverStderr.String()) {
		if time.Now().After(deadline) {
			client.Process.Kill()
			t.Fatalf("server never logged dropping the SYN to unserved port %v; server stderr:\n%s", unservedPort, serverStderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	client.Process.Kill()
	client.Wait()
	if clientOut.Len() > 0 {
		t.Errorf("client to unserved port %v got output %q; want none", unservedPort, clientOut.String())
	}
}

// TestServeExitNode verifies that a --serve=exit-node server forwards
// connections to arbitrary IP:port destinations, both for a plain
// client given an IP:port argument and through the SOCKS5 proxy that
// "tailcat socks" runs.
func TestServeExitNode(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	port := startEchoListener(t)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	_, addr, serverStderr := e.startServer("--verbose", "--serve=exit-node")

	t.Run("client_ipport", func(t *testing.T) {
		const payload = "echo through the exit node"
		got, err := runClient(t, e.cmd("--verbose", "--key=new", "--derpmap-url="+e.derpMapURL, addr, dst.String()), serverStderr, payload)
		if err != nil {
			t.Fatalf("client to %v: %v", dst, err)
		}
		if got != payload {
			t.Errorf("exit node echoed %q; want %q", got, payload)
		}
	})

	t.Run("socks5", func(t *testing.T) {
		socks := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "socks", addr)
		socksErr, err := socks.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := socks.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { socks.Process.Kill() })

		// The proxy logs its listen address to stderr once it's ready.
		addrRx := regexp.MustCompile(`socks5h://(\S+)`)
		proxyAddr := ""
		scanner := bufio.NewScanner(socksErr)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("socks: %s", line)
			if m := addrRx.FindStringSubmatch(line); m != nil {
				proxyAddr = m[1]
				break
			}
		}
		if proxyAddr == "" {
			t.Fatal("never saw the SOCKS proxy address on stderr")
		}

		c := socks5Connect(t, proxyAddr, dst)
		defer c.Close()
		const payload = "echo through SOCKS and the exit node"
		if _, err := c.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("reading echo reply: %v", err)
		}
		if got := string(buf); got != payload {
			t.Errorf("SOCKS echoed %q; want %q", got, payload)
		}
	})
}

// socks5Connect dials the SOCKS5 proxy at proxyAddr and issues a
// CONNECT to the IPv4 destination dst, returning the proxied
// connection. It hand-rolls the tiny client side of RFC 1928 rather
// than adding a dependency on golang.org/x/net/proxy.
func socks5Connect(t *testing.T, proxyAddr string, dst netip.AddrPort) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil { // version 5, one method: no auth
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 5 || buf[1] != 0 {
		t.Fatalf("SOCKS5 method reply = %v; want [5 0]", buf)
	}

	ip4 := dst.Addr().As4()
	req := append([]byte{5, 1, 0, 1}, ip4[:]...) // CONNECT, IPv4
	req = append(req, byte(dst.Port()>>8), byte(dst.Port()))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4) // version, code, reserved, bind address type
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT reply code = %d; want 0", reply[1])
	}
	var bindLen int
	switch reply[3] {
	case 1: // IPv4
		bindLen = 4
	case 4: // IPv6
		bindLen = 16
	default:
		t.Fatalf("SOCKS5 CONNECT reply address type = %d; want 1 or 4", reply[3])
	}
	if _, err := io.ReadFull(c, make([]byte, bindLen+2)); err != nil { // bind address and port
		t.Fatal(err)
	}
	c.SetDeadline(time.Time{})
	return c
}
