// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// directtest is the helper behind the direct-connection GitHub
// Actions workflow (.github/workflows/direct-connection.yml), which
// checks whether two Actions runner VMs can reach each other over a
// direct (non-DERP) path.
//
// It runs in two modes on two machines. The server mode loads a
// server key made by "tailcat genkey --fixed-region", serves a line
// echo on TCP port 1 to a single allowlisted client, and polls
// [tailcat.Server.Status] to report whether the client's path is
// direct or relayed, since only the server side exposes that view.
// The client mode connects to the server's tailcat address, checks
// connectivity with a round trip through the echo service, and then
// sends disco pings for a while, hoping one comes back directly. Both
// modes exit non-zero if connectivity fails and warn (but exit zero)
// if the path stays relayed; the point of the workflow is to find
// out, not to insist.
//
//	directtest server --key=server.private.json --allow=nodekey:... [--timeout=4m]
//	directtest client --key=client.private.json [--connect-timeout=3m] [--direct-timeout=30s] <tc-addr>
package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  directtest server --key=<file> --allow=<nodekey> [--timeout=4m]\n  directtest client --key=<file> [--connect-timeout=3m] [--direct-timeout=30s] <tc-addr>")
	os.Exit(2)
}

// loadKey reads a *.private.json file written by "tailcat genkey".
func loadKey(path string) (*tailcat.PrivateKey, error) {
	j, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	conf := new(tailcat.PrivateKey)
	if err := json.Unmarshal(j, conf); err != nil {
		return nil, fmt.Errorf("parsing %v: %w", path, err)
	}
	return conf, nil
}

// echoPort is the TCP port on the server's tailcat address that the
// server echoes lines on and the client uses for its connectivity
// check.
const echoPort = 1

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the server's *.private.json from tailcat genkey")
	allow := fs.String("allow", "", "the one client node key (nodekey:...) allowed to connect")
	timeout := fs.Duration("timeout", 4*time.Minute, "give up if the client hasn't connected and finished by then")
	fs.Parse(args)
	if *keyPath == "" || *allow == "" || fs.NArg() != 0 {
		usage()
	}
	var clientKey key.NodePublic
	if err := clientKey.UnmarshalText([]byte(*allow)); err != nil {
		return fmt.Errorf("bad --allow: %w", err)
	}
	conf, err := loadKey(*keyPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// The key from genkey --fixed-region names a region ID; resolve it
	// to the region's DERP nodes so Start doesn't run a netcheck.
	ci := conf.Public
	if err := ci.Expand(ctx, tailcat.ExpandForServer); err != nil {
		return fmt.Errorf("resolving DERP region: %w", err)
	}
	s := &tailcat.Server{
		Key:          conf.Private,
		PresharedKey: conf.Public.PresharedKey,
		Region:       ci.Region[0],
		AllowClient:  func(k key.NodePublic) bool { return k == clientKey },
		Logf:         logger.WithPrefix(log.Printf, "[tailcat] "),
	}
	defer s.Close()
	ln, err := s.Listen(ctx, "tcp", fmt.Sprintf(":%d", echoPort))
	if err != nil {
		return fmt.Errorf("Listen: %w", err)
	}
	defer ln.Close()
	log.Printf("serving; tailcat address: %v", s.TailcatAddr())
	log.Printf("allowed client: %v", clientKey)

	// The client holds one TCP connection open for as long as it wants
	// the server to keep watching, so its close is the end signal.
	connected := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- fmt.Errorf("Accept: %w", err)
			return
		}
		log.Printf("client connected over the tunnel from %v", c.RemoteAddr())
		close(connected)
		done <- echoLines(c)
	}()

	var last pathState
	var sawDirect bool
	poll := func() {
		ps, ok := s.Status().Peer[clientKey]
		if !ok {
			return
		}
		cur := pathStateOf(ps)
		if cur != last {
			log.Printf("peer status: %v", cur)
			last = cur
		}
		if cur.direct() {
			sawDirect = true
		}
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for clientDone := false; !clientDone; {
		select {
		case <-tick.C:
			poll()
		case err := <-done:
			if err != nil {
				return err
			}
			clientDone = true
		case <-ctx.Done():
			select {
			case <-connected:
				return fmt.Errorf("client connected but hadn't finished after %v", *timeout)
			default:
				return fmt.Errorf("no client connected within %v", *timeout)
			}
		}
	}
	// The client closes as soon as its own view turns direct, which
	// can run a moment ahead of the server's status, so give that a
	// few seconds to catch up before reporting.
	settle := time.Now().Add(3 * time.Second)
	for poll(); !sawDirect && time.Now().Before(settle); poll() {
		time.Sleep(200 * time.Millisecond)
	}
	log.Printf("client finished; final peer status: %v", last)
	report("server", sawDirect, last.String())
	return nil
}

// echoLines echoes lines from c back to it until the client closes
// the connection.
func echoLines(c net.Conn) error {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading from client: %w", err)
		}
		if _, err := io.WriteString(c, line); err != nil {
			return fmt.Errorf("writing to client: %w", err)
		}
	}
}

// pathState is the part of an [ipnstate.PeerStatus] that says how
// the peer is reached.
type pathState struct {
	curAddr string
	relay   string
}

func pathStateOf(ps *ipnstate.PeerStatus) pathState {
	return pathState{curAddr: ps.CurAddr, relay: ps.Relay}
}

// direct reports whether the peer currently has a direct path.
func (p pathState) direct() bool { return p.curAddr != "" }

func (p pathState) String() string {
	if p.direct() {
		return fmt.Sprintf("direct via %v (relay %v)", p.curAddr, cmp.Or(p.relay, "none"))
	}
	if p.relay == "" {
		return "no path yet"
	}
	return fmt.Sprintf("relayed via DERP %v", p.relay)
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the client's *.private.json from tailcat genkey --client")
	connectTimeout := fs.Duration("connect-timeout", 3*time.Minute, "how long to keep trying to reach the server, which may still be starting up")
	directTimeout := fs.Duration("direct-timeout", 30*time.Second, "how long to keep pinging for a direct path once connected")
	fs.Parse(args)
	if *keyPath == "" || fs.NArg() != 1 {
		usage()
	}
	conf, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	cl := &tailcat.Client{
		Server: tailcat.Addr(fs.Arg(0)),
		Key:    conf.Private,
		Logf:   logger.WithPrefix(log.Printf, "[tailcat] "),
	}
	defer cl.Close()
	log.Printf("client node key: %v", cl.PublicKey())

	// The server job is starting up in parallel and may not be on
	// DERP yet; each Ping gives up after 10 seconds, so keep retrying
	// until the connect timeout.
	ctx, cancel := context.WithTimeout(context.Background(), *connectTimeout)
	defer cancel()
	t0 := time.Now()
	for {
		res, err := cl.Ping(ctx)
		if err == nil {
			log.Printf("server reachable over DERP after %v; relay round trip %v", time.Since(t0).Round(time.Millisecond), res.Latency.Round(time.Millisecond))
			break
		}
		if ctx.Err() != nil {
			return fmt.Errorf("server not reachable within %v: %v", *connectTimeout, err)
		}
		log.Printf("ping: %v; retrying", err)
	}

	c, err := cl.DialTCPPort(ctx, echoPort)
	if err != nil {
		return fmt.Errorf("dialing echo port over the tunnel: %w", err)
	}
	defer c.Close()
	const hello = "hello from the client job\n"
	if _, err := io.WriteString(c, hello); err != nil {
		return fmt.Errorf("writing to echo server: %w", err)
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading echo reply: %w", err)
	}
	if got != hello {
		return fmt.Errorf("echo reply %q doesn't match what was sent %q", got, hello)
	}
	log.Printf("TCP echo round trip through the tunnel succeeded")

	// Ping about once a second until a pong comes back over a direct
	// path or time runs out. DiscoPing also nudges direct path
	// discovery along, so this loop is what upgrades the connection.
	deadline := time.Now().Add(*directTimeout)
	var direct bool
	var lastVia string
	for time.Now().Before(deadline) {
		t0 := time.Now()
		pingCtx, cancel := context.WithDeadline(ctx, deadline)
		res, err := cl.DiscoPing(pingCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			return fmt.Errorf("disco ping: %w", err)
		}
		latency := time.Duration(res.LatencySeconds * float64(time.Second)).Round(10 * time.Microsecond)
		if res.Endpoint != "" {
			lastVia = "direct via " + res.Endpoint
			log.Printf("pong in %v %v", latency, lastVia)
			direct = true
			break
		}
		lastVia = fmt.Sprintf("relayed via DERP %v", cmp.Or(res.DERPRegionCode, res.DERPRegionID.String()))
		log.Printf("pong in %v %v", latency, lastVia)
		time.Sleep(max(0, time.Second-time.Since(t0)))
	}
	if lastVia == "" {
		lastVia = "no pong received"
	}
	if !direct {
		log.Printf("no direct path after %v", *directTimeout)
	}
	// Closing the echo connection tells the server we're done.
	c.Close()
	report("client", direct, lastVia)
	return nil
}

// report writes the outcome to the log and, when running under GitHub
// Actions, to the job summary, with a warning annotation if the path
// never became direct. Connectivity is a hard requirement checked by
// the callers; being direct is what the workflow exists to find out.
func report(side string, direct bool, path string) {
	verdict := "RELAYED"
	if direct {
		verdict = "DIRECT"
	}
	log.Printf("%s result: %s (%s)", side, verdict, path)
	if !direct {
		fmt.Printf("::warning title=%s stayed relayed::no direct path between the runner VMs; %s\n", side, path)
	}
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryPath == "" {
		return
	}
	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("opening GITHUB_STEP_SUMMARY: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "## %s: %s\n\nConnectivity through the tunnel worked. Path as seen by the %s: %s.\n", side, verdict, side, path)
}
