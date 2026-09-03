// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
)

// twoRegionCLIEnv is a testEnv whose DERP map has two localhost
// relays, as regions 1 and 2. --auto-region needs that: a stale
// address names region 1 while the server is actually on 2.
func twoRegionCLIEnv(t *testing.T) *testEnv {
	t.Helper()
	bin := buildTailcat(t)

	a := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	b := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	r1, r2 := a.Regions[1], b.Regions[1]
	if r1 == nil || r2 == nil {
		t.Fatal("no region 1 in a test DERP map")
	}
	r1.RegionName = "Test Region 1"
	r2.RegionID, r2.RegionCode, r2.RegionName = 2, "test2", "Test Region 2"
	for _, n := range r1.Nodes {
		n.HostName = "t1.test"
	}
	for _, n := range r2.Nodes {
		n.RegionID, n.Name, n.HostName = 2, "t2", "t2.test"
	}
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: r1, 2: r2}}
	dmJSON, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	dmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dmJSON)
	}))
	t.Cleanup(dmSrv.Close)

	return &testEnv{
		t:          t,
		bin:        bin,
		derpMapURL: dmSrv.URL,
		env:        append(os.Environ(), cacheEnv(t)...),
	}
}

func staleRegionAddr(t *testing.T, addr string, region tailcfg.DERPRegionID) string {
	t.Helper()
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatal(err)
	}
	ci.Region, ci.RegionID = nil, region
	return string(ci.Addr())
}

func runPing(t *testing.T, e *testEnv, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := e.cmd(args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(90 * time.Second):
			cmd.Process.Kill()
		}
	}()
	err = cmd.Run()
	close(done)
	return outBuf.String(), errBuf.String(), err
}

// TestAutoRegionPing is the CLI acceptance test for --auto-region:
// a server bound to region 2, an address rewritten to name region 1,
// then ping without the flag (must fail) and with it (must find the
// server, print a pong on stdout, and put the corrected address on
// stderr).
func TestAutoRegionPing(t *testing.T) {
	e := twoRegionCLIEnv(t)

	keyFile := filepath.Join(t.TempDir(), "server.private.json")
	gen := e.cmd("--derpmap-url="+e.derpMapURL, "genkey", "--key="+keyFile, "--region=2")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("genkey --region=2: %v\n%s", err, out)
	}

	_, addr, _ := e.startServer("--key=" + keyFile)
	ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatal(err)
	}
	if ci.RegionID != 2 {
		t.Fatalf("server address RegionID = %v; want 2", ci.RegionID)
	}
	stale := staleRegionAddr(t, addr, 1)

	stdout, stderr, err := runPing(t, e, "--key=new", "--derpmap-url="+e.derpMapURL, "ping", "--timeout=5s", stale)
	if err == nil {
		t.Fatalf("ping without --auto-region succeeded; want failure\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}

	stdout, stderr, err = runPing(t, e, "--key=new", "--derpmap-url="+e.derpMapURL, "--auto-region", "--verbose", "ping", stale)
	if err != nil {
		t.Fatalf("ping --auto-region: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	// stdout is the ProxyCommand tunnel in the other client modes, so
	// nothing about the search may appear on it.
	if !strings.Contains(stdout, "pong") {
		t.Errorf("stdout = %q; want a pong line", stdout)
	}
	if strings.Contains(stdout, "auto-region") || strings.Contains(stdout, "region 2") {
		t.Errorf("stdout = %q; the region notice must go to stderr", stdout)
	}
	if !strings.Contains(stderr, "region 2") {
		t.Errorf("stderr = %q; want the corrected region 2 notice", stderr)
	}
	if !strings.Contains(stderr, "its current address is:") {
		t.Errorf("stderr = %q; want the corrected address", stderr)
	}
	if !strings.Contains(stderr, "auto-region:") {
		t.Errorf("verbose stderr = %q; want per-region auto-region progress", stderr)
	}
}
