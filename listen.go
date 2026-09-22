// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"

	"tailscale.com/util/mak"
)

// Listen announces on the given port of the server's tailcat address and
// returns a listener for incoming connections from clients.
//
// The network must be "tcp", "tcp6", "udp", or "udp6". The address must name
// a port (":8080", ":http") with an empty host, an unspecified address such
// as "::", or the server's own address. A port of 0 picks an unused port,
// retrievable from the returned listener's Addr method.
//
// For UDP networks, each Accept returns a [net.Conn] that also implements
// [ConnPacketConn], one per client flow, subject to [Server.UDPIdleTimeout],
// exactly as with [Server.OnUDP].
//
// If the server has not yet been started, Listen starts it, and ctx bounds
// that startup work (fetching the DERP map and picking a region). After
// Listen returns, ctx has no further effect on the listener; use the
// listener's Close method instead.
//
// Connections and flows to a port with an active listener are delivered to
// that listener and are never offered to [Server.OnTCP] or [Server.OnUDP].
func (s *Server) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var udp bool
	switch network {
	case "tcp", "tcp6":
	case "udp", "udp6":
		udp = true
	default:
		return nil, fmt.Errorf("tailcat: Listen: unsupported network %q", network)
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("tailcat: Listen: %w", err)
	}
	portNum, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("tailcat: Listen: %w", err)
	}

	s.startMu.Lock()
	if s.lb == nil {
		if err := s.startLocked(ctx); err != nil {
			s.startMu.Unlock()
			return nil, err
		}
	}
	s.startMu.Unlock()

	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("tailcat: Listen: invalid host %q in address %q", host, address)
		}
		if !ip.IsUnspecified() && ip != s.Addr() {
			return nil, fmt.Errorf("tailcat: Listen: host %v is not the server's address %v", ip, s.Addr())
		}
	}

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	m := &s.tcpListeners
	if udp {
		m = &s.udpListeners
	}
	port := uint16(portNum)
	if portNum == 0 {
		port, err = pickUnusedPort(*m)
		if err != nil {
			return nil, err
		}
	}
	if _, dup := (*m)[port]; dup {
		return nil, fmt.Errorf("tailcat: Listen: %s port %d already in use", network, port)
	}
	ln := &listener{
		s:       s,
		udp:     udp,
		port:    port,
		conns:   make(chan net.Conn),
		closedc: make(chan struct{}),
	}
	mak.Set(m, port, ln)
	s.installFilterLocked()
	return ln, nil
}

// pickUnusedPort returns a port in the dynamic range that is not a key of m,
// scanning linearly from a random starting point.
func pickUnusedPort(m map[uint16]*listener) (uint16, error) {
	const lo, hi = 32768, 60999
	const n = hi - lo + 1
	start := rand.Intn(n)
	for i := range n {
		p := uint16(lo + (start+i)%n)
		if _, used := m[p]; !used {
			return p, nil
		}
	}
	return 0, errors.New("tailcat: Listen: no unused ports")
}

// listenerForPort returns the active listener for the given network ("tcp" or
// "udp") and port on the server's own address, or nil if there is none.
func (s *Server) listenerForPort(network string, port uint16) *listener {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	if network == "udp" {
		return s.udpListeners[port]
	}
	return s.tcpListeners[port]
}

// listener is a net.Listener accepting incoming connections or UDP flows on
// one port of the server's own tailcat address. See [Server.Listen].
type listener struct {
	s    *Server
	udp  bool
	port uint16

	conns   chan net.Conn // handed from netstack flow handlers to Accept
	closedc chan struct{} // closed when the listener is closed

	closed bool // guarded by s.listenerMu
}

// handle delivers c to a pending Accept call, blocking until one is ready.
// If the listener closes first, c is closed instead. It runs on the
// per-connection goroutine that netstack starts for each new flow.
func (ln *listener) handle(c net.Conn) {
	select {
	case ln.conns <- c:
	case <-ln.closedc:
		c.Close()
	}
}

// Accept waits for and returns the next connection. For UDP listeners, the
// returned [net.Conn] is one client flow and also implements [ConnPacketConn].
func (ln *listener) Accept() (net.Conn, error) {
	return ln.AcceptContext(context.Background())
}

// ContextListener is a listener whose pending accepts can be cancelled without
// closing the listener. Listeners returned by Server.Listen implement it.
type ContextListener interface {
	net.Listener
	AcceptContext(context.Context) (net.Conn, error)
}

// AcceptContext waits for a connection, listener closure, or cancellation.
func (ln *listener) AcceptContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c := <-ln.conns:
		return c, nil
	case <-ln.closedc:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Addr returns the listener's address: the server's tailcat address and the
// listening port.
func (ln *listener) Addr() net.Addr {
	ip := net.IP(ln.s.lb.addr.AsSlice())
	if ln.udp {
		return &net.UDPAddr{IP: ip, Port: int(ln.port)}
	}
	return &net.TCPAddr{IP: ip, Port: int(ln.port)}
}

// Close stops the listener and releases its port; traffic to the port once
// again goes to [Server.OnTCP] or [Server.OnUDP]. Pending and future Accept
// calls return [net.ErrClosed]. Already accepted connections are unaffected.
func (ln *listener) Close() error {
	ln.s.listenerMu.Lock()
	defer ln.s.listenerMu.Unlock()
	return ln.closeLocked(true)
}

// closeLocked implements Close. installFilter says whether to reinstall the
// packet filter, which [Server.Close] skips because the whole engine is
// shutting down. s.listenerMu must be held.
func (ln *listener) closeLocked(installFilter bool) error {
	if ln.closed {
		return net.ErrClosed
	}
	ln.closed = true
	s := ln.s
	if ln.udp {
		delete(s.udpListeners, ln.port)
	} else {
		delete(s.tcpListeners, ln.port)
	}
	close(ln.closedc)
	if installFilter {
		s.installFilterLocked()
	}
	return nil
}
