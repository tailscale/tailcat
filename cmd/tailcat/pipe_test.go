// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLocalDERPMode runs the built tailcat binary in server mode with
// TS_DEBUG_TAILCAT_LOCAL_DERP=1, which starts a DERP server on
// localhost and embeds it in the tailcat address, then round-trips a
// payload from a client using that address. Both sides get a
// --derpmap-url pointing at an unreachable address to prove the whole
// exchange is hermetic. The Homebrew formula test relies on this mode
// (plus TAILCAT_ADDR_FILE) to test the bottles without network
// access, so it must not regress.
func TestLocalDERPMode(t *testing.T) {
	t.Parallel()
	bin := buildTailcat(t)

	const derpMapURL = "none"
	addrFile := filepath.Join(t.TempDir(), "addr")

	server := exec.Command(bin, "--key=new", "--derpmap-url="+derpMapURL)
	server.Env = append(append(os.Environ(), cacheEnv(t)...),
		"TS_DEBUG_TAILCAT_LOCAL_DERP=1",
		"TAILCAT_ADDR_FILE="+addrFile)
	var serverOut bytes.Buffer
	var serverErr lockedBuf
	server.Stdout = &serverOut
	server.Stderr = &serverErr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Process.Kill()

	addr := waitAddr(t, addrFile, &serverErr)

	const payload = "hello hermetic world"
	client := exec.Command(bin, "--key=new", "--derpmap-url="+derpMapURL, addr)
	client.Env = append(os.Environ(), cacheEnv(t)...)
	client.Stdin = strings.NewReader(payload)
	var clientErr bytes.Buffer
	client.Stderr = &clientErr
	if err := client.Run(); err != nil {
		t.Fatalf("client: %v\nclient stderr:\n%s", err, clientErr.String())
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server exited with error: %v\nserver stderr:\n%s", err, serverErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("server did not exit within 15s of the transfer completing\nserver stderr:\n%s", serverErr.String())
	}
	if got := serverOut.String(); got != payload {
		t.Errorf("server got %q; want %q", got, payload)
	}
}

// TestPipeMode runs the built tailcat binary in its two stdin/stdout
// pipe modes against a local DERP server, emulating a pipeline like
// "tailcat | tar -zx" on the server side and "tar -zc | tailcat
// <tc-addr>" on the client side. Both processes must exit on their own
// once the client's stdin hits EOF: the server must see the client's
// half-close as EOF, and the client must see the server's close (the
// server must not exit before its FIN is delivered, which once made
// clients hang forever).
func TestPipeMode(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)

	server, addrFile := e.serverCmd()
	serverOut, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var serverErr lockedBuf
	server.Stderr = &serverErr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Process.Kill()

	addr := waitAddr(t, addrFile, &serverErr)

	client := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, addr)
	const payload = "pretend this is a tarball"
	client.Stdin = strings.NewReader(payload)
	var clientOut, clientErr bytes.Buffer
	client.Stdout = &clientOut
	client.Stderr = &clientErr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Process.Kill()

	// Emulate "tar -zxv" on the server side: read server stdout until EOF.
	serverGotEOF := make(chan string, 1)
	go func() {
		all, _ := io.ReadAll(serverOut)
		serverGotEOF <- string(all)
	}()

	select {
	case got := <-serverGotEOF:
		t.Logf("server stdout closed; got %q", got)
		if got != payload {
			t.Errorf("server got %q; want %q", got, payload)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("server side never saw EOF after 30s\nserver stderr:\n%s\nclient stderr:\n%s", serverErr.String(), clientErr.String())
	}

	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Errorf("client exited with error: %v\nclient stderr:\n%s", err, clientErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Errorf("client did not exit within 15s of the transfer completing\nclient stderr:\n%s", clientErr.String())
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("server exited with error: %v\nserver stderr:\n%s", err, serverErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Errorf("server did not exit within 15s of the transfer completing\nserver stderr:\n%s", serverErr.String())
	}
}
