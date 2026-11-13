// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"tailscale.com/tstest/integration"
	"tailscale.com/wgengine/filter"
)

// TestExecConnHandlerResetBeforeServed covers a client that resets its
// connection between the handshake and the handler starting: gonet
// then reports nil local and remote addresses.
func TestExecConnHandlerResetBeforeServed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clientAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	serverAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	clientStack, clientLink := newTestTCPStack(t, clientAddr)
	serverStack, serverLink := newTestTCPStack(t, serverAddr)
	go relayTestPackets(ctx, clientLink, serverLink, nil)
	go relayTestPackets(ctx, serverLink, clientLink, nil)

	ln, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{NIC: testNICID, Addr: serverAddr, Port: 1234}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()
	client, err := gonet.DialTCP(clientStack, tcpip.FullAddress{NIC: testNICID, Addr: serverAddr, Port: 1234}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	server := <-accepted
	defer server.Close()

	ep, _ := gonetTCPConnInternals(client)
	ep.(tcpip.Endpoint).Abort() // sends a RST
	for deadline := time.Now().Add(5 * time.Second); server.RemoteAddr() != nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("server never saw the client's reset")
		}
	}

	ran := filepath.Join(t.TempDir(), "ran")
	s := &Server{lb: &locoBackend{logf: t.Logf}}
	s.ExecConnHandler([]string{"/bin/sh", "-c", "touch " + ran})(server)
	if _, err := os.Stat(ran); err == nil {
		t.Error("the command ran for a connection that was already reset")
	}
}

// TestServerSurvivesHandlerPanic checks that a panic in one
// connection's handler doesn't take the server down with it.
func TestServerSurvivesHandlerPanic(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	s := &Server{Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port == 81 {
			return func(net.Conn) { panic("handler bug") }
		}
		return func(c net.Conn) {
			io.WriteString(c, "ok")
			c.Close()
		}
	}
	s.ServedTCPPorts = []filter.PortRange{{First: 80, Last: 81}}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bad, err := c.DialTCPPort(ctx, 81)
	if err != nil {
		t.Fatalf("DialTCPPort(81): %v", err)
	}
	bad.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(bad); err != nil {
		t.Logf("port 81 read: %v", err)
	}
	bad.Close()

	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort(80) after the panic: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "ok" {
		t.Fatalf("port 80 after the panic = %q, %v; want %q", got, err, "ok")
	}
}
