// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
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
