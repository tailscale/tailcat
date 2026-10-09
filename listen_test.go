// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/wgengine/filter"
)

func TestListen(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	s := &Server{Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != 80 && port != 81 {
			return nil
		}
		return func(c net.Conn) {
			io.WriteString(c, "hook\n")
			c.Close()
		}
	}
	// The restricted port set makes the filter side load-bearing below:
	// the auto-picked listener port only works if listener ports are
	// admitted in addition to ServedTCPPorts, and the UDP listener only
	// works if it admits UDP with OnUDP unset.
	s.ServedTCPPorts = []filter.PortRange{{First: 80, Last: 81}}

	ctx := t.Context()

	// The first Listen implicitly starts the server.
	ln80, err := s.Listen(ctx, "tcp", ":80")
	if err != nil {
		t.Fatalf(`Listen("tcp", ":80"): %v`, err)
	}
	lnAuto, err := s.Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatalf(`Listen("tcp", ":0"): %v`, err)
	}
	autoPort := uint16(lnAuto.Addr().(*net.TCPAddr).Port)
	if autoPort == 0 {
		t.Fatal("Listen picked port 0")
	}
	lnUDP, err := s.Listen(ctx, "udp", ":9999")
	if err != nil {
		t.Fatalf(`Listen("udp", ":9999"): %v`, err)
	}
	if ua, ok := lnUDP.Addr().(*net.UDPAddr); !ok || ua.Port != 9999 {
		t.Fatalf("UDP listener Addr = %v; want a *net.UDPAddr with port 9999", lnUDP.Addr())
	}

	if err := s.Start(); err == nil {
		t.Fatal("Start after Listen succeeded; want already-started error")
	}

	for _, tt := range []struct{ network, address string }{
		{"tcp4", ":80"},       // IPv4 network on an IPv6-only server
		{"unix", ":80"},       // unsupported network
		{"tcp", "80"},         // missing colon
		{"tcp", ":80"},        // TCP port already taken
		{"udp", ":9999"},      // UDP port already taken
		{"tcp", "1.2.3.4:99"}, // not the server's address
	} {
		if ln, err := s.Listen(ctx, tt.network, tt.address); err == nil {
			ln.Close()
			t.Errorf("Listen(%q, %q) succeeded; want error", tt.network, tt.address)
		}
	}
	// The server's own address is an acceptable host.
	lnSelf, err := s.Listen(ctx, "tcp", net.JoinHostPort(s.Addr().String(), "0"))
	if err != nil {
		t.Fatalf("Listen on the server's own address: %v", err)
	}
	lnSelf.Close()

	serve := func(ln net.Listener, msg string) {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				io.WriteString(c, msg)
				c.Close()
			}
		}()
	}
	serve(ln80, "listener 80\n")
	serve(lnAuto, "listener auto\n")

	// One UDP flow arrives below; echo it uppercased and report whether
	// the accepted conn implements ConnPacketConn.
	udpConnOK := make(chan bool, 1)
	go func() {
		c, err := lnUDP.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, ok := c.(ConnPacketConn)
		udpConnOK <- ok
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		c.Write(bytes.ToUpper(buf[:n]))
	}()

	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	readTCP := func(port uint16) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		conn, err := c.DialTCPPort(ctx, port)
		if err != nil {
			t.Fatalf("DialTCPPort(%d): %v", port, err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		all, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("reading from port %d: %v", port, err)
		}
		return string(all)
	}
	if got := readTCP(80); got != "listener 80\n" {
		t.Errorf("port 80 = %q; want the listener to win over OnTCP", got)
	}
	if got := readTCP(81); got != "hook\n" {
		t.Errorf("port 81 = %q; want the OnTCP fallback", got)
	}
	if got := readTCP(autoPort); got != "listener auto\n" {
		t.Errorf("auto port %d = %q; want the listener", autoPort, got)
	}

	pc, err := c.DialUDPPort(t.Context(), 9999)
	if err != nil {
		t.Fatalf("DialUDPPort(9999): %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.Write([]byte("meow")); err != nil {
		t.Fatalf("UDP write: %v", err)
	}
	buf := make([]byte, 32)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("UDP read: %v", err)
	}
	if got := string(buf[:n]); got != "MEOW" {
		t.Errorf("UDP echo = %q; want %q", got, "MEOW")
	}
	if !<-udpConnOK {
		t.Error("accepted UDP conn does not implement ConnPacketConn")
	}

	// Closing a listener returns its port to OnTCP.
	if err := ln80.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	if err := ln80.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Close = %v; want net.ErrClosed", err)
	}
	if _, err := ln80.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v; want net.ErrClosed", err)
	}
	if got := readTCP(80); got != "hook\n" {
		t.Errorf("port 80 after listener Close = %q; want the OnTCP fallback", got)
	}
}
