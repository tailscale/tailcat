// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// TestRunConnCommandInteractive covers a command that reads a line from
// the connection, replies, and exits while the client keeps its sending
// side open. The client's input must reach the command before the
// command exits, and runConnCommand must return once it has exited
// rather than waiting for the client to half-close.
func TestRunConnCommandInteractive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- runConnCommand(server, exec.Command("/bin/sh", "-c", "read line; echo got $line"))
	}()

	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(client, "hi\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "got hi\n" {
		t.Errorf("got %q; want %q", got, "got hi\n")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runConnCommand: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runConnCommand didn't return after the command exited")
	}
}
