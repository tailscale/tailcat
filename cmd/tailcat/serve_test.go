// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/nettype"
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

// runClient runs an unstarted tailcat client command with payload on
// its stdin and a 60 second watchdog, returning its stdout and error.
// The watchdog only exists to catch true hangs; it's generous because
// a loaded machine can drop relayed packets and leave the transfer
// waiting out TCP retransmit backoff. On failure, the error includes
// the client's stderr and the given server stderr (which may be nil),
// so both sides of a wedged conversation are visible.
func runClient(t *testing.T, client *exec.Cmd, serverStderr *bytes.Buffer, payload string) (string, error) {
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

	got, err = runClient(t, e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr, strconv.Itoa(unservedPort)), serverStderr, payload)
	if err == nil {
		t.Errorf("client to unserved port %v succeeded with output %q; want connection failure", unservedPort, got)
	}
}

// TestServeExitNode verifies that a --serve=exit-node server forwards
// connections to arbitrary IP:port destinations, both for a plain
// client given an IP:port argument and through the SOCKS5 proxy that
// "tailcat socks" runs.
func TestServeExitNode(t *testing.T) {
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

func TestServeExitNodeUDP(t *testing.T) {
	e := newTestEnv(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()

	_, addr, _ := e.startServer("--serve=exit-node")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := tailcat.NewClient(tailcat.Addr(addr))
	client.DERPMapURL = e.derpMapURL
	defer client.Close()

	conn, err := client.DialUDP(ctx, dst)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	const msg = "udp echo through tailcat exit node"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write UDP: %v", err)
	}

	replyBuf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(replyBuf)
	if err != nil {
		t.Fatalf("Read UDP reply: %v", err)
	}
	if string(replyBuf[:n]) != msg {
		t.Fatalf("UDP echo got %q, want %q", string(replyBuf[:n]), msg)
	}

	if !client.HasServerCap(tailcat.CapExitUDP) {
		t.Errorf("server did not advertise CapExitUDP: caps = %02x", client.ServerCaps())
	}

	if _, err := conn.Write([]byte{}); err != nil {
		t.Fatalf("Write zero-length UDP: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	zeroReply := make([]byte, 100)
	nZero, err := conn.Read(zeroReply)
	if err != nil {
		t.Fatalf("Read zero-length UDP reply: %v", err)
	}
	if nZero != 0 {
		t.Fatalf("expected zero-length reply, got %d bytes", nZero)
	}
}

func TestAllowProxyRejection(t *testing.T) {
	e := newTestEnv(t)

	var tcpForwardInvoked atomic.Bool
	var udpForwardInvoked atomic.Bool

	echoPort := startEchoListener(t)
	allowedDst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), echoPort)
	prohibitedDst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 80)

	srv := &tailcat.Server{
		DERPMapURL: e.derpMapURL,
		AllowProxy: func(dst netip.AddrPort) bool {
			return dst == allowedDst
		},
		OnTCPForward: func(dst netip.AddrPort) func(net.Conn) {
			tcpForwardInvoked.Store(true)
			return func(c net.Conn) { c.Close() }
		},
		OnUDPForward: func(dst netip.AddrPort) func(nettype.ConnPacketConn) {
			udpForwardInvoked.Store(true)
			return func(c nettype.ConnPacketConn) { c.Close() }
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := tailcat.NewClient(srv.TailcatAddr())
	client.DERPMapURL = e.derpMapURL
	defer client.Close()

	tcpConn, err := client.DialTCP(ctx, prohibitedDst)
	if err == nil {
		buf := make([]byte, 10)
		_ = tcpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = tcpConn.Read(buf)
		tcpConn.Close()
	}
	if tcpForwardInvoked.Load() {
		t.Errorf("OnTCPForward was invoked for prohibited destination %v", prohibitedDst)
	}

	udpConn, err := client.DialUDP(ctx, prohibitedDst)
	if err == nil {
		_, _ = udpConn.Write([]byte("prohibited-udp-packet"))
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 100)
		_, _ = udpConn.Read(buf)
		udpConn.Close()
	}
	if udpForwardInvoked.Load() {
		t.Errorf("OnUDPForward was invoked for prohibited destination %v", prohibitedDst)
	}
}
