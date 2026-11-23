// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
)

func forwardCommand(parent *ff.FlagSet) *ff.Command {
	fs := ff.NewFlagSet("forward").SetParent(parent)
	bind := fs.StringLong("bind", "127.0.0.1", "listen address; used as the local address when a mapping only specifies a port")
	openBrowser := fs.BoolLong("open-browser", "open a web browser to the local listener once it's listening; requires exactly one TCP port mapping")
	return &ff.Command{
		Name:      "forward",
		Usage:     "tailcat forward [flags] <tc-addr> <[local:]remote-port|local-port:remote-ip:remote-port|socket-path:remote-port> [<...> ...]",
		ShortHelp: "forward local TCP ports or Unix sockets to a tailcat server",
		LongHelp: `Listen on local TCP ports or Unix sockets and forward connections to a tailcat server.

A mapping with one port uses the same local and remote port. A mapping with
local:remote uses different local and remote ports. A local port of 0 asks
the operating system for a free port; each listener prints its address once
it's listening. A mapping with a remote IP address and port requires the
server to be running as an exit node. A mapping whose first component is not
a number uses a local Unix socket path and remote port. For example:

	tailcat forward <tc-addr> 8080
	tailcat forward --bind=0.0.0.0 <tc-addr> 18080:8080
	tailcat forward <tc-addr> 0:8080
	tailcat forward <tc-addr> 13306:192.168.1.10:3306
	tailcat forward <tc-addr> /tmp/server.sock:80`,
		Flags: fs,
		Exec: func(ctx context.Context, args []string) error {
			var onListen func(net.Listener)
			if *openBrowser {
				if len(args) > 2 {
					return usagef("--open-browser requires exactly one port mapping")
				}
				onListen = openBrowserToListener
			}
			return runForward(ctx, getLogf(), *bind, args, onListen)
		},
	}
}

type forwardSpec struct {
	listenNetwork string
	listenAddr    string
	target        netip.AddrPort
	port          uint16
}

func (s forwardSpec) remoteTarget() string {
	if s.target.IsValid() {
		return s.target.String()
	}
	return net.JoinHostPort("localhost", strconv.Itoa(int(s.port)))
}

// runForward listens on the local addresses named by the mappings in
// args and forwards accepted connections to the tailcat server. If
// onListen is non-nil, it is called once per listener after it starts
// listening.
func runForward(ctx context.Context, logf logger.Logf, bind string, args []string, onListen func(net.Listener)) error {
	if len(args) < 2 {
		return usagef("forward takes a <tc-addr> and at least one port mapping")
	}

	cl := newClient(logf, tailcatAddrArg(args[0]), clientKey())
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	listeners := make([]net.Listener, 0, len(args)-1)
	var listenersWG, connectionsWG sync.WaitGroup
	var active sync.Map
	defer func() {
		stop()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		listenersWG.Wait()
		active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		connectionsWG.Wait()
		_ = cl.Close()
	}()
	for _, spec := range args[1:] {
		mapping, err := parseForwardSpec(bind, spec)
		if err != nil {
			for _, ln := range listeners {
				ln.Close()
			}
			return usagef("mapping %q is invalid: %v", spec, err)
		}
		if onListen != nil && mapping.listenNetwork != "tcp" {
			for _, ln := range listeners {
				ln.Close()
			}
			return usagef("--open-browser requires a TCP port mapping")
		}
		ln, err := net.Listen(mapping.listenNetwork, mapping.listenAddr)
		if err != nil {
			for _, old := range listeners {
				old.Close()
			}
			return fmt.Errorf("listen on %s: %w", mapping.listenAddr, err)
		}
		listeners = append(listeners, ln)
		// Print unconditionally (not via the verbose-only logf): with a
		// local port of 0 this line is the only way to learn which port
		// the OS picked.
		fmt.Fprintf(os.Stderr, "# forwarding %s -> remote %s\n", ln.Addr(), mapping.remoteTarget())
		if onListen != nil {
			onListen(ln)
		}
		listenersWG.Add(1)
		go forwardListener(ctx, logf, cl, ln, mapping, &listenersWG, &connectionsWG, &active)
	}

	<-ctx.Done()
	for _, ln := range listeners {
		ln.Close()
	}
	return nil
}

func forwardListener(ctx context.Context, logf logger.Logf, cl *tailcat.Client, ln net.Listener, mapping forwardSpec, listenersWG, connectionsWG *sync.WaitGroup, active *sync.Map) {
	defer listenersWG.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		connectionsWG.Add(1)
		active.Store(conn, struct{}{})
		go func() {
			defer connectionsWG.Done()
			defer active.Delete(conn)
			defer conn.Close()
			var remote net.Conn
			var err error
			if mapping.target.IsValid() {
				remote, err = cl.DialTCP(ctx, mapping.target)
			} else {
				remote, err = cl.DialTCPPort(ctx, mapping.port)
			}
			if err != nil {
				if ctx.Err() == nil {
					logf("dial remote target %s: %v", mapping.remoteTarget(), err)
				}
				return
			}
			tailcat.ProxyConns(conn, remote)
		}()
	}
}

func parseForwardSpec(bind, spec string) (forwardSpec, error) {
	local, target, hasColon := strings.Cut(spec, ":")
	if !isDecimal(local) {
		colon := strings.LastIndex(spec, ":")
		if colon <= 0 {
			return forwardSpec{}, fmt.Errorf("Unix socket mapping %q must include a remote port", spec)
		}
		remotePort, err := parseForwardPort(spec[colon+1:])
		if err != nil {
			return forwardSpec{}, fmt.Errorf("remote port: %w", err)
		}
		return forwardSpec{
			listenNetwork: "unix",
			listenAddr:    spec[:colon],
			port:          remotePort,
		}, nil
	}
	if !hasColon {
		target = local
	}
	var localPort uint16
	var err error
	if !hasColon || local != "0" { // local port 0 asks the OS for a free port
		localPort, err = parseForwardPort(local)
		if err != nil {
			return forwardSpec{}, fmt.Errorf("local port: %w", err)
		}
	}
	mapping := forwardSpec{
		listenNetwork: "tcp",
		listenAddr:    net.JoinHostPort(bind, strconv.Itoa(int(localPort))),
	}
	if !hasColon {
		mapping.port, err = parseForwardPort(target)
		if err != nil {
			return forwardSpec{}, fmt.Errorf("remote port: %w", err)
		}
		return mapping, nil
	}
	remotePort, err := parseForwardPort(target)
	if err == nil {
		mapping.port = remotePort
		return mapping, nil
	}
	remoteAddr, err := netip.ParseAddrPort(target)
	if err != nil {
		return forwardSpec{}, fmt.Errorf("remote target %q is not a port or address:port", target)
	}
	mapping.target = remoteAddr
	return mapping, nil
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseForwardPort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(p), nil
}
