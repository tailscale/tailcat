// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	"github.com/tailscale/tailcat/internal/perf"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

const perfLongHelp = `Run a throughput and latency test against a "tailcat serve perf"
server, in the style of iperf. The client sends to the server by
default; --reverse sends the other way and --bidir both ways at once.
Progress prints every --interval, then a summary with both sides'
counts and, for UDP, loss, reordering, and jitter. Round trips over
the test's control connection measure latency while the tunnel is
loaded. Examples:

	tailcat perf <tc-addr>
	tailcat perf --reverse --time=30s <tc-addr>
	tailcat perf --udp --bitrate=50M <tc-addr>
	tailcat perf --parallel=4 --bytes=1G <tc-addr>
	tailcat --json perf <tc-addr>

The test first waits for a direct (non-DERP) path, up to --timeout,
and refuses to run through a DERP relay otherwise: a throughput test
through a shared relay mostly measures its rate limit while crowding
out everyone else using it. --via-derp allows a relayed test through
a relay you run yourself. Tailscale's shared relays (*.ipn.dev,
*.tailscale.com) are always refused.`

func perfCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("perf").SetParent(parent)
	udp := fs.BoolLong("udp", "test UDP instead of TCP")
	reverse := fs.BoolLong("reverse", "have the server send to the client instead of the client sending to the server")
	bidir := fs.BoolLong("bidir", "send in both directions at once")
	duration := fs.DurationLong("time", 10*time.Second, "how long to send")
	bytesFlag := fs.StringLong("bytes", "", "send this many bytes per stream instead of sending for --time, with an optional K, M, or G suffix (powers of 1000)")
	parallel := fs.IntLong("parallel", 1, "number of parallel streams")
	length := fs.IntLong("length", 0, fmt.Sprintf("bytes per TCP write or UDP datagram. If 0, %d for TCP and %d for UDP, the largest datagram that fits the tunnel's MTU", defaultTCPLength, tailcat.MaxUDPPayload))
	bitrate := fs.StringLong("bitrate", "", "target bits per second per stream, with an optional K, M, or G suffix, or 0 for as fast as possible. If empty, as fast as possible for TCP and 1M for UDP")
	interval := fs.DurationLong("interval", time.Second, "how often to print progress; 0 disables progress lines")
	timeout := fs.DurationLong("timeout", 10*time.Second, "how long to wait for a direct path before giving up (or, with --via-derp, running relayed)")
	viaDERP := fs.BoolLong("via-derp", "run the test even if the path stays relayed through a DERP server, unless the relay is one of Tailscale's shared ones")
	return &ff.Command{
		Name:      "perf",
		Usage:     "tailcat perf [flags] <tc-addr>",
		ShortHelp: "measure throughput and latency to a server (iperf-like)",
		LongHelp:  perfLongHelp,
		Flags:     fs,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return usagef("perf requires one <tc-addr> argument")
			}
			if *reverse && *bidir {
				return usagef("--reverse and --bidir are exclusive")
			}
			p := perf.Params{
				Proto:     perf.TCP,
				Direction: perf.Upload,
				Duration:  *duration,
				Streams:   *parallel,
				Length:    *length,
				Interval:  *interval,
			}
			if *udp {
				p.Proto = perf.UDP
				p.Bitrate = 1_000_000
			}
			if *reverse {
				p.Direction = perf.Download
			}
			if *bidir {
				p.Direction = perf.Bidirectional
			}
			if *bytesFlag != "" {
				n, err := parseSI(*bytesFlag)
				if err != nil || n <= 0 {
					return usagef("invalid --bytes value %q", *bytesFlag)
				}
				p.Bytes = n
				p.Duration = 0
			}
			if *bitrate != "" {
				n, err := parseSI(*bitrate)
				if err != nil || n < 0 {
					return usagef("invalid --bitrate value %q", *bitrate)
				}
				p.Bitrate = n
			}
			if p.Length == 0 {
				p.Length = defaultTCPLength
				if *udp {
					p.Length = tailcat.MaxUDPPayload
				}
			}
			if *parallel < 1 {
				return usagef("--parallel must be at least 1")
			}
			if p.Bytes == 0 && p.Duration <= 0 {
				return usagef("--time must be positive")
			}
			return runPerf(ctx, getLogf(), args[0], p, *timeout, *viaDERP, *flagJSON)
		},
	}
}

// defaultTCPLength is the default size of each TCP write.
const defaultTCPLength = 128 << 10

// parseSI parses a number with an optional K, M, or G suffix meaning
// powers of 1000, as in "10M" or "1.5G".
func parseSI(s string) (int64, error) {
	mult := 1.0
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 'k', 'K':
			mult = 1e3
		case 'm', 'M':
			mult = 1e6
		case 'g', 'G':
			mult = 1e9
		}
		if mult != 1 {
			s = s[:n-1]
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	v := f * mult
	if math.IsNaN(v) || v > math.MaxInt64 || v < math.MinInt64 {
		return 0, errors.New("out of range")
	}
	return int64(v), nil
}

// pathInfo is what a disco ping reported about the path to the server.
type pathInfo struct {
	Direct     bool          `json:"direct"`
	Endpoint   string        `json:"endpoint,omitempty"`   // the direct path's IP:port
	DERPRegion string        `json:"derpRegion,omitempty"` // the relay's region code, if relayed
	RTT        time.Duration `json:"rtt"`
}

func (p pathInfo) String() string {
	if p.Direct {
		return fmt.Sprintf("direct via %v, rtt %v", p.Endpoint, fmtRTT(p.RTT))
	}
	return fmt.Sprintf("relayed via DERP(%v), rtt %v", p.DERPRegion, fmtRTT(p.RTT))
}

// probePath sends one disco ping and reports the path its pong took.
func probePath(ctx context.Context, cl *tailcat.Client) (pathInfo, error) {
	res, err := cl.DiscoPing(ctx)
	if err != nil {
		return pathInfo{}, err
	}
	p := pathInfo{
		Direct:   res.Endpoint != "",
		Endpoint: res.Endpoint,
		RTT:      time.Duration(res.LatencySeconds * float64(time.Second)),
	}
	if !p.Direct {
		p.DERPRegion = cmp.Or(res.DERPRegionCode, res.DERPRegionID.String())
	}
	return p, nil
}

// waitForDirectPath pings the server until a pong arrives over a
// direct path or timeout passes, returning the last path seen. Like
// "tailcat ping --until-direct", the pings themselves drive path
// discovery along.
func waitForDirectPath(ctx context.Context, cl *tailcat.Client, timeout time.Duration) (pathInfo, error) {
	deadline := time.Now().Add(timeout)
	for {
		t0 := time.Now()
		pingCtx, cancel := context.WithDeadline(ctx, deadline)
		p, err := probePath(pingCtx, cl)
		cancel()
		if err != nil {
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return pathInfo{}, fmt.Errorf("no reply to pings after %v", timeout)
			}
			return pathInfo{}, err
		}
		if p.Direct || time.Until(deadline) < time.Second/2 {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return pathInfo{}, ctx.Err()
		case <-time.After(max(0, time.Second-time.Since(t0))):
		}
	}
}

// sharedTailscaleDERP reports whether r is one of Tailscale's shared
// DERP relays, by hostname, returning the first such hostname. These
// relays are rate-limited and shared with everyone, so throughput
// tests are refused through them even with --via-derp.
func sharedTailscaleDERP(r *tailcfg.DERPRegion) (hostname string, ok bool) {
	if r == nil {
		return "", false
	}
	for _, n := range r.Nodes {
		h := strings.ToLower(strings.TrimSuffix(n.HostName, "."))
		if strings.HasSuffix(h, ".ipn.dev") || strings.HasSuffix(h, ".tailscale.com") {
			return n.HostName, true
		}
	}
	return "", false
}

// perfOutput is the --json output of a perf test.
type perfOutput struct {
	Path      pathInfo  `json:"path"`                // before the test
	PathAfter *pathInfo `json:"pathAfter,omitempty"` // after the test, if it could be measured
	*perf.Result
}

func runPerf(ctx context.Context, logf logger.Logf, addrArg string, p perf.Params, timeout time.Duration, viaDERP, asJSON bool) error {
	cl := newClient(logf, tailcatAddrArg(addrArg), clientKey())
	defer cl.Close()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	before, err := waitForDirectPath(ctx, cl, timeout)
	if err != nil {
		return fmt.Errorf("perf: %w", err)
	}
	fmt.Fprintf(os.Stderr, "# path: %v\n", before)
	if !before.Direct {
		if !viaDERP {
			return fmt.Errorf("perf: no direct path to the server after %v; refusing to run a throughput test through a DERP relay (--via-derp allows it, for a relay you run yourself)", timeout)
		}
		if host, ok := sharedTailscaleDERP(cl.DERPRegion()); ok {
			return fmt.Errorf("perf: refusing to run a throughput test through Tailscale's shared DERP relay %v; --via-derp is only for relays you run yourself", host)
		}
	}
	if p.Proto == perf.UDP && p.Length > tailcat.MaxUDPPayload {
		fmt.Fprintf(os.Stderr, "# ⚠️ WARNING: %d-byte datagrams exceed the tunnel MTU's %d-byte payload and may not arrive\n", p.Length, tailcat.MaxUDPPayload)
	}

	pc := &perf.Client{
		DialTCP: func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, perf.Port) },
		DialUDP: func(ctx context.Context) (net.Conn, error) { return cl.DialUDPPort(ctx, perf.Port) },
	}
	if !asJSON {
		fmt.Println(describePerfTest(p))
		if p.Interval > 0 {
			pc.OnProgress = func(pr perf.Progress) { fmt.Println(perfProgressLine(p, pr)) }
		}
	}
	res, err := pc.Run(ctx, p)
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("perf: interrupted")
		}
		return fmt.Errorf("perf: %w", err)
	}

	// The path can change during a test, most often upgrading from
	// the relay to a direct path partway through, which makes the
	// numbers hard to interpret without knowing.
	var after *pathInfo
	afterCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	if pa, err := probePath(afterCtx, cl); err == nil {
		after = &pa
	}
	cancel()

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "\t")
		return enc.Encode(perfOutput{Path: before, PathAfter: after, Result: res})
	}
	for _, line := range perfResultLines(res) {
		fmt.Println(line)
	}
	if after != nil && after.Direct != before.Direct {
		fmt.Fprintf(os.Stderr, "# path changed during the test, now: %v\n", *after)
	}
	return nil
}

// describePerfTest returns the line printed before a test starts.
func describePerfTest(p perf.Params) string {
	var sb strings.Builder
	sb.WriteString(strings.ToUpper(string(p.Proto)))
	sb.WriteString(", ")
	sb.WriteString(perfDirectionName(p.Direction))
	fmt.Fprintf(&sb, ", %d stream", p.Streams)
	if p.Streams != 1 {
		sb.WriteString("s")
	}
	if p.Bytes > 0 {
		fmt.Fprintf(&sb, ", %v per stream", fmtBytes(p.Bytes))
	} else {
		fmt.Fprintf(&sb, ", %v", p.Duration)
	}
	if p.Bitrate > 0 {
		fmt.Fprintf(&sb, ", %v per stream", fmtBitrate(float64(p.Bitrate)))
	}
	return sb.String()
}

func perfDirectionName(d perf.Direction) string {
	switch d {
	case perf.Upload:
		return "client -> server"
	case perf.Download:
		return "server -> client"
	default:
		return "both directions"
	}
}

// perfProgressLine formats one interval's progress.
func perfProgressLine(p perf.Params, pr perf.Progress) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%6.1fs]", pr.Elapsed.Seconds())
	if p.Direction != perf.Download {
		fmt.Fprintf(&sb, "  sent %9v %13v", fmtBytes(pr.Sent.Bytes), fmtRate(pr.Sent.Bytes, p.Interval))
	}
	if p.Direction != perf.Upload {
		fmt.Fprintf(&sb, "  received %9v %13v", fmtBytes(pr.Received.Bytes), fmtRate(pr.Received.Bytes, p.Interval))
	}
	if pr.RTT > 0 {
		fmt.Fprintf(&sb, "  rtt %v", fmtRTT(pr.RTT))
	}
	return sb.String()
}

// perfResultLines formats a test's summary.
func perfResultLines(res *perf.Result) []string {
	var lines []string
	pair := func(indent string, sent, recv *perf.Stats) {
		if sent == nil || recv == nil {
			return
		}
		s := fmt.Sprintf("%ssent      %9v in %6.1fs %13v", indent, fmtBytes(sent.Bytes), sent.Duration.Seconds(), fmtRate(sent.Bytes, sent.Duration))
		r := fmt.Sprintf("%sreceived  %9v in %6.1fs %13v", indent, fmtBytes(recv.Bytes), recv.Duration.Seconds(), fmtRate(recv.Bytes, recv.Duration))
		if res.Params.Proto == perf.UDP {
			s += fmt.Sprintf("  %d datagrams", sent.Datagrams)
			lost := sent.Datagrams - recv.Datagrams
			pct := 0.0
			if sent.Datagrams > 0 {
				pct = float64(lost) / float64(sent.Datagrams) * 100
			}
			r += fmt.Sprintf("  %d datagrams, %d lost (%.1f%%), %d reordered, jitter %v", recv.Datagrams, lost, pct, recv.Reordered, fmtRTT(recv.Jitter))
		}
		lines = append(lines, s, r)
	}
	if res.Params.Direction == perf.Bidirectional {
		lines = append(lines, "client -> server:")
		pair("  ", res.ClientSent, res.ServerReceived)
		lines = append(lines, "server -> client:")
		pair("  ", res.ServerSent, res.ClientReceived)
	} else {
		pair("", res.ClientSent, res.ServerReceived)
		pair("", res.ServerSent, res.ClientReceived)
	}
	if rtt := res.RTT; rtt != nil {
		lines = append(lines, fmt.Sprintf("rtt under load  min %v  avg %v  max %v  (%d samples)", fmtRTT(rtt.Min), fmtRTT(rtt.Avg), fmtRTT(rtt.Max), rtt.Count))
	}
	return lines
}

// perfSummary returns the one-line summary the server logs per test:
// the received rate in each direction, and UDP loss.
func perfSummary(res *perf.Result) string {
	rate := func(sent, recv *perf.Stats) string {
		if recv == nil {
			return "?"
		}
		s := fmtRate(recv.Bytes, recv.Duration)
		if res.Params.Proto == perf.UDP && sent != nil && sent.Datagrams > 0 {
			s += fmt.Sprintf(" (%.1f%% lost)", float64(sent.Datagrams-recv.Datagrams)/float64(sent.Datagrams)*100)
		}
		return s
	}
	proto := strings.ToUpper(string(res.Params.Proto))
	switch res.Params.Direction {
	case perf.Upload:
		return fmt.Sprintf("%v client -> server %v", proto, rate(res.ClientSent, res.ServerReceived))
	case perf.Download:
		return fmt.Sprintf("%v server -> client %v", proto, rate(res.ServerSent, res.ClientReceived))
	default:
		return fmt.Sprintf("%v client -> server %v, server -> client %v", proto, rate(res.ClientSent, res.ServerReceived), rate(res.ServerSent, res.ClientReceived))
	}
}

// fmtSI formats v to three significant digits with an SI prefix and
// unit, as in "1.18 GB" or "943 Mbit/s".
func fmtSI(v float64, unit string) string {
	prefixes := []string{"", "K", "M", "G", "T"}
	i := 0
	for v >= 1000 && i < len(prefixes)-1 {
		v /= 1000
		i++
	}
	switch {
	case i == 0:
		return fmt.Sprintf("%.0f %s", v, unit)
	case v >= 100:
		return fmt.Sprintf("%.0f %s%s", v, prefixes[i], unit)
	case v >= 10:
		return fmt.Sprintf("%.1f %s%s", v, prefixes[i], unit)
	default:
		return fmt.Sprintf("%.2f %s%s", v, prefixes[i], unit)
	}
}

func fmtBytes(n int64) string { return fmtSI(float64(n), "B") }

func fmtBitrate(bps float64) string { return fmtSI(bps, "bit/s") }

// fmtRate formats n bytes over d as a bitrate.
func fmtRate(n int64, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmtBitrate(float64(n) * 8 / d.Seconds())
}

func fmtRTT(d time.Duration) time.Duration { return d.Round(10 * time.Microsecond) }
