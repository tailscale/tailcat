// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat/internal/perf"
	"tailscale.com/tailcfg"
)

// TestPerf runs TCP and UDP tests against a "serve perf" server over
// the localhost direct path the harness provides. It checks the shape
// of the output and that both ends agree on the byte counts, never
// the throughput itself.
func TestPerf(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	_, addr, serverStderr := e.startServer("serve", "perf")
	waitForLog(t, serverStderr, "Accepting perf tests")

	perfCmd := func(t *testing.T, args ...string) []byte {
		t.Helper()
		all := append([]string{"--key=new", "--derpmap-url=" + e.derpMapURL, "perf", "--timeout=30s", "--time=1s", "--interval=500ms"}, args...)
		all = append(all, addr)
		out, err := e.cmd(all...).CombinedOutput()
		if err != nil {
			t.Fatalf("perf %v: %v\n%s", args, err, out)
		}
		return out
	}

	t.Run("tcp", func(t *testing.T) {
		out := perfCmd(t)
		for _, want := range []*regexp.Regexp{
			regexp.MustCompile(`(?m)^# path: direct via `),
			regexp.MustCompile(`(?m)^TCP, client -> server, 1 stream, 1s$`),
			regexp.MustCompile(`(?m)^\[ +0\.5s\]  sent +\S+ [KMG]?B +\S+ [KMG]?bit/s`),
			regexp.MustCompile(`(?m)^sent +\S+ [KMG]?B in +\S+s +\S+ [KMG]?bit/s$`),
			regexp.MustCompile(`(?m)^received +\S+ [KMG]?B in +\S+s +\S+ [KMG]?bit/s$`),
			regexp.MustCompile(`(?m)^rtt under load  min \S+  avg \S+  max \S+  \(\d+ samples\)$`),
		} {
			if !want.Match(out) {
				t.Errorf("output missing %v:\n%s", want, out)
			}
		}
		waitForLog(t, serverStderr, "# perf test from ")
		if !strings.Contains(serverStderr.String(), "TCP client -> server ") {
			t.Errorf("server log missing test summary:\n%s", serverStderr.String())
		}
	})

	t.Run("udp_reverse_json", func(t *testing.T) {
		out := perfCmd(t, "--udp", "--reverse", "--parallel=2", "--bitrate=4M", "--json")
		// Status lines go to stderr; the JSON document is everything
		// from the first brace on.
		i := strings.Index(string(out), "{")
		if i < 0 {
			t.Fatalf("no JSON in output:\n%s", out)
		}
		var got struct {
			Path struct {
				Direct bool `json:"direct"`
			} `json:"path"`
			perf.Result
		}
		if err := json.Unmarshal(out[i:], &got); err != nil {
			t.Fatalf("decoding JSON: %v\n%s", err, out)
		}
		if !got.Path.Direct {
			t.Errorf("path not direct")
		}
		if got.Params.Proto != perf.UDP || got.Params.Direction != perf.Download || got.Params.Streams != 2 || got.Params.Bitrate != 4_000_000 {
			t.Errorf("unexpected params %+v", got.Params)
		}
		if got.ServerSent == nil || got.ClientReceived == nil {
			t.Fatalf("missing server -> client stats in %+v", got.Result)
		}
		if got.ServerSent.Datagrams < 10 {
			t.Errorf("server sent only %d datagrams", got.ServerSent.Datagrams)
		}
		// A paced 4 Mbit/s over localhost shouldn't lose anything,
		// but the userspace stack under a loaded CI machine may drop
		// a few; the counts must at least be close.
		if lost := got.ServerSent.Datagrams - got.ClientReceived.Datagrams; lost < 0 || lost*10 > got.ServerSent.Datagrams {
			t.Errorf("server sent %d datagrams, client received %d", got.ServerSent.Datagrams, got.ClientReceived.Datagrams)
		}
		if got.ClientSent != nil || got.ServerReceived != nil {
			t.Errorf("reverse test reported client -> server stats")
		}
		if got.RTT == nil || got.RTT.Count == 0 {
			t.Errorf("no RTT samples in %+v", got.Result)
		}
	})
}

// TestPerfServeRejectsPortClash checks that a port list can't proxy
// the port the perf service owns.
func TestPerfServeRejectsPortClash(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	out, err := e.cmd("--key=new", "--derpmap-url="+e.derpMapURL, "serve", "perf,5201").CombinedOutput()
	if err == nil {
		t.Fatalf("serve perf,5201 succeeded; want failure\n%s", out)
	}
	if !strings.Contains(string(out), "used by the 'perf' service") {
		t.Errorf("unexpected error output:\n%s", out)
	}
}

func TestSharedTailscaleDERP(t *testing.T) {
	region := func(hosts ...string) *tailcfg.DERPRegion {
		r := &tailcfg.DERPRegion{}
		for _, h := range hosts {
			r.Nodes = append(r.Nodes, &tailcfg.DERPNode{HostName: h})
		}
		return r
	}
	tests := []struct {
		r    *tailcfg.DERPRegion
		want string
	}{
		{nil, ""},
		{region(), ""},
		{region("derp.example.com"), ""},
		{region("tc302a.ipn.dev"), "tc302a.ipn.dev"},
		{region("derp1.tailscale.com."), "derp1.tailscale.com."},
		{region("DERP2.Tailscale.COM"), "DERP2.Tailscale.COM"},
		{region("derp.example.com", "tc1.ipn.dev"), "tc1.ipn.dev"},
		{region("ipn.dev.example.com"), ""},
		{region("nottailscale.com"), ""},
	}
	for _, tt := range tests {
		got, ok := sharedTailscaleDERP(tt.r)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("sharedTailscaleDERP(%v) = %q, %v; want %q", tt.r, got, ok, tt.want)
		}
	}
}

func TestParseSI(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		err  bool
	}{
		{"0", 0, false},
		{"1234", 1234, false},
		{"10K", 10_000, false},
		{"10k", 10_000, false},
		{"1.5M", 1_500_000, false},
		{"2G", 2_000_000_000, false},
		{"", 0, true},
		{"M", 0, true},
		{"1X", 0, true},
		{"1e400", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSI(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("parseSI(%q) = %d, %v; want %d, err=%v", tt.in, got, err, tt.want, tt.err)
		}
	}
}

func TestFmtSI(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1000, "1.00 KB"},
		{12_345, "12.3 KB"},
		{123_456, "123 KB"},
		{1_180_000_000, "1.18 GB"},
	}
	for _, tt := range tests {
		if got := fmtBytes(tt.n); got != tt.want {
			t.Errorf("fmtBytes(%d) = %q; want %q", tt.n, got, tt.want)
		}
	}
	if got := fmtRate(1_180_000_000, 10*time.Second); got != "944 Mbit/s" {
		t.Errorf("fmtRate = %q", got)
	}
	if got := fmtRate(1, 0); got != "-" {
		t.Errorf("fmtRate over zero duration = %q", got)
	}
}
