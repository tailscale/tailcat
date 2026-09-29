// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package capi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const ABIVersion = 1
const TCP = 1
const UDP = 2

type ClientConfig struct {
	Address    string `json:"address"`
	Key        string `json:"key,omitempty"`
	DERPMapURL string `json:"derp_map_url,omitempty"`
}

type ServerConfig struct {
	Key            string               `json:"key,omitempty"`
	PresharedKey   string               `json:"preshared_key,omitempty"`
	Region         *tailcfg.DERPRegion  `json:"region,omitempty"`
	RegionID       tailcfg.DERPRegionID `json:"region_id,omitempty"`
	DERPMapURL     string               `json:"derp_map_url,omitempty"`
	AllowedClients []string             `json:"allowed_clients,omitempty"`
	UDPIdleTimeout float64              `json:"udp_idle_timeout,omitempty"`
}

// ready records a successful first operation; DrainTCP is only valid afterwards.
type client struct {
	client *tailcat.Client
	ready  atomic.Bool
}

type server struct {
	server  *tailcat.Server
	gate    gate
	started bool
}

type listener struct {
	ln      tailcat.ContextListener
	network int
}

type connection struct {
	conn       net.Conn
	readGate   gate
	writeGate  gate
	network    int
	reads      chan readResult
	stopped    chan struct{}
	pumpDone   chan struct{}
	closeOnce  sync.Once
	pending    []byte // guarded by readGate
	pendingBuf []byte // backing buffer of pending
	readError  error  // guarded by readGate
}

type readResult struct {
	buf  []byte
	data []byte
	err  error
}

const readBufferSize = 32 * 1024

var readBuffers = sync.Pool{New: func() any {
	b := make([]byte, readBufferSize)
	return &b
}}

func (c *connection) take(result readResult, ok bool) {
	c.pending, c.pendingBuf, c.readError = result.data, result.buf, result.err
	if !ok {
		c.readError = io.EOF
	}
	c.release()
}

func (c *connection) release() {
	if len(c.pending) == 0 && c.pendingBuf != nil {
		b := c.pendingBuf
		c.pending, c.pendingBuf = nil, nil
		readBuffers.Put(&b)
	}
}

func newConnection(conn net.Conn, network int) *connection {
	c := &connection{conn: conn, readGate: newGate(), writeGate: newGate(), network: network,
		stopped: make(chan struct{}), pumpDone: make(chan struct{})}
	if network == TCP {
		c.reads = make(chan readResult, 1)
		go c.receive()
	} else {
		close(c.pumpDone)
	}
	return c
}

// receive owns all TCP reads and has bounded backpressure. gVisor checks expired
// deadlines before readable state, so setting an immediate deadline is not a
// reliable EOF probe. This queue provides non-consuming readiness without an OS
// descriptor, and never retains a caller's memory across an ABI call.
func (c *connection) receive() {
	defer close(c.pumpDone)
	defer close(c.reads)
	for {
		b := *readBuffers.Get().(*[]byte)
		n, err := c.conn.Read(b)
		if n == 0 && err == nil {
			readBuffers.Put(&b)
			continue
		}
		select {
		case c.reads <- readResult{b, b[:n], err}:
		case <-c.stopped:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *connection) close() {
	c.closeOnce.Do(func() {
		close(c.stopped)
		c.conn.Close()
	})
}

func (c *connection) readTCP(ctx context.Context, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 && c.readError == nil {
		select {
		case result, ok := <-c.reads:
			c.take(result, ok)
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if len(c.pending) > 0 {
		n := copy(data, c.pending)
		c.pending = c.pending[n:]
		c.release()
		return n, nil
	}
	return 0, c.readError
}

// Decoder errors may quote the input, which can contain secrets; only the
// unknown-field error, which names just the field, is passed through.
func decode(config string, target any) error {
	d := json.NewDecoder(strings.NewReader(config))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return fmt.Errorf("%w: %v", ErrArgument, err)
		}
		return fmt.Errorf("%w: invalid configuration", ErrArgument)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%w: trailing configuration data", ErrArgument)
	}
	return nil
}

func nodeKey(text string) (key.NodePrivate, error) {
	if text == "" {
		return key.NewNode(), nil
	}
	var k key.NodePrivate
	if err := k.UnmarshalText([]byte(text)); err != nil || k.IsZero() {
		return k, fmt.Errorf("%w: invalid private key", ErrArgument)
	}
	return k, nil
}

func NewClient(config string) (Handle, error) {
	var cfg ClientConfig
	if err := decode(config, &cfg); err != nil {
		return 0, err
	}
	ci, err := tailcat.ParseAddr(tailcat.Addr(cfg.Address))
	if err != nil || ci.ServerDiscoPublic.IsZero() {
		return 0, fmt.Errorf("%w: invalid or unsupported tailcat address", ErrArgument)
	}
	k, err := nodeKey(cfg.Key)
	if err != nil {
		return 0, err
	}
	return register(&client{client: &tailcat.Client{Server: tailcat.Addr(cfg.Address), Key: k, DERPMapURL: cfg.DERPMapURL, Logf: logger.Discard}}, 0)
}

func NewServer(config string) (Handle, error) {
	var cfg ServerConfig
	if err := decode(config, &cfg); err != nil {
		return 0, err
	}
	k, err := nodeKey(cfg.Key)
	if err != nil {
		return 0, err
	}
	psk := tailcat.NewPresharedKey()
	if cfg.PresharedKey != "" {
		if err := psk.UnmarshalText([]byte(cfg.PresharedKey)); err != nil || psk.IsZero() {
			return 0, fmt.Errorf("%w: invalid pre-shared key", ErrArgument)
		}
	}
	if cfg.UDPIdleTimeout < 0 || cfg.UDPIdleTimeout > float64(int64(^uint64(0)>>1))/float64(time.Second) {
		return 0, fmt.Errorf("%w: invalid UDP idle timeout", ErrArgument)
	}
	s := &tailcat.Server{Key: k, PresharedKey: psk, Region: cfg.Region, RegionID: cfg.RegionID, DERPMapURL: cfg.DERPMapURL, Logf: logger.Discard, UDPIdleTimeout: time.Duration(cfg.UDPIdleTimeout * float64(time.Second))}
	for _, text := range cfg.AllowedClients {
		var pub key.NodePublic
		if err := pub.UnmarshalText([]byte(text)); err != nil || pub.IsZero() {
			return 0, fmt.Errorf("%w: invalid allowed client key", ErrArgument)
		}
		s.AllowedClients = append(s.AllowedClients, pub)
	}
	return register(&server{server: s, gate: newGate()}, 0)
}

func publishConnection(ctx context.Context, parent Handle, conn net.Conn, network int) (Handle, error) {
	if err := ctx.Err(); err != nil {
		conn.Close()
		return 0, err
	}
	c := newConnection(conn, network)
	h, err := register(c, parent)
	if err != nil {
		c.close()
		<-c.pumpDone
	}
	return h, err
}

func Dial(id, token Handle, port uint16, network int) (result Handle, err error) {
	if port == 0 || (network != TCP && network != UDP) {
		return 0, ErrArgument
	}
	err = use[*client](id, token, func(ctx context.Context, e *entry, c *client) error {
		var conn net.Conn
		var err error
		if network == TCP {
			conn, err = c.client.DialTCPPort(ctx, port)
		} else {
			conn, err = c.client.DialUDPPort(ctx, port)
		}
		if err != nil {
			return err
		}
		c.ready.Store(true)
		result, err = publishConnection(ctx, e.id, conn, network)
		return err
	})
	return
}

// startLocked starts the server once; the caller holds s.gate.
func (s *server) startLocked(ctx context.Context) error {
	if s.started {
		return nil
	}
	if err := s.server.StartContext(ctx); err != nil {
		return err
	}
	s.started = true
	return nil
}

func Start(id, token Handle) error {
	return use[*server](id, token, func(ctx context.Context, e *entry, s *server) error {
		if err := s.gate.lock(ctx); err != nil {
			return err
		}
		defer s.gate.unlock()
		return s.startLocked(ctx)
	})
}

func Listen(id, token Handle, port uint16, network int) (result Handle, err error) {
	if network != TCP && network != UDP {
		return 0, ErrArgument
	}
	err = use[*server](id, token, func(ctx context.Context, e *entry, s *server) error {
		if err := s.gate.lock(ctx); err != nil {
			return err
		}
		defer s.gate.unlock()
		if err := s.startLocked(ctx); err != nil {
			return err
		}
		n := "tcp"
		if network == UDP {
			n = "udp"
		}
		ln, err := s.server.Listen(ctx, n, fmt.Sprintf(":%d", port))
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			ln.Close()
			return err
		}
		result, err = register(&listener{ln: ln.(tailcat.ContextListener), network: network}, e.id)
		if err != nil {
			ln.Close()
		}
		return err
	})
	return
}

func Accept(id, token Handle) (result Handle, err error) {
	err = use[*listener](id, token, func(ctx context.Context, e *entry, l *listener) error {
		conn, err := l.ln.AcceptContext(ctx)
		if err != nil {
			return err
		}
		result, err = publishConnection(ctx, e.parent, conn, l.network)
		return err
	})
	return
}

// withDeadline serializes operations in one direction, including waiting for the
// gate in their deadlines. The cancellation callback is joined before clearing
// the deadline, so it cannot poison a later operation on the same connection.
func withDeadline(ctx context.Context, g gate, set func(time.Time) error, fn func() error) error {
	if err := g.lock(ctx); err != nil {
		return err
	}
	defer g.unlock()
	deadline, _ := ctx.Deadline()
	if err := set(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { set(time.Now()); close(done) })
	err := fn()
	if !stop() {
		<-done
	}
	set(time.Time{})
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func Read(id, token Handle, data []byte) (n int, err error) {
	err = use[*connection](id, token, func(ctx context.Context, e *entry, c *connection) error {
		if c.network == TCP {
			if err := c.readGate.lock(ctx); err != nil {
				return err
			}
			defer c.readGate.unlock()
			var err error
			n, err = c.readTCP(ctx, data)
			return err
		}
		return withDeadline(ctx, c.readGate, c.conn.SetReadDeadline, func() error {
			var err error
			n, err = c.conn.Read(data)
			return err
		})
	})
	return
}

func Write(id, token Handle, data []byte) (n int, err error) {
	err = use[*connection](id, token, func(ctx context.Context, e *entry, c *connection) error {
		if c.network == UDP && len(data) > tailcat.MaxUDPPayload {
			return fmt.Errorf("%w: datagram exceeds MaxUDPPayload", ErrArgument)
		}
		return withDeadline(ctx, c.writeGate, c.conn.SetWriteDeadline, func() error {
			var err error
			n, err = c.conn.Write(data)
			return err
		})
	})
	return
}

func CloseWrite(id, token Handle) error {
	return use[*connection](id, token, func(ctx context.Context, e *entry, c *connection) error {
		if err := c.writeGate.lock(ctx); err != nil {
			return err
		}
		defer c.writeGate.unlock()
		cw, ok := c.conn.(interface{ CloseWrite() error })
		if !ok {
			return fmt.Errorf("%w: half-close requires TCP", ErrArgument)
		}
		return cw.CloseWrite()
	})
}

// Readable performs a non-consuming probe for connection-pool expiry. It never
// waits behind a concurrent reader. For idle TCP, data or EOF both expire HTTP/1.
func Readable(id Handle) (bool, error) {
	e, err := borrow(id)
	if err != nil {
		return true, err
	}
	defer e.active.Done()
	c, ok := e.value.(*connection)
	if !ok || c.network != TCP {
		return false, ErrType
	}
	select {
	case c.readGate <- struct{}{}:
	default:
		return false, nil
	}
	defer c.readGate.unlock()
	if len(c.pending) > 0 || c.readError != nil {
		return true, nil
	}
	select {
	case result, ok := <-c.reads:
		c.take(result, ok)
		return true, nil
	default:
		return false, nil
	}
}

func Info(id, token Handle) (out string, err error) {
	err = use[any](id, token, func(ctx context.Context, e *entry, v any) error {
		var info any
		switch v := v.(type) {
		case *client:
			info = map[string]any{"public_key": v.client.PublicKey().String()}
		case *server:
			if err := v.gate.lock(ctx); err != nil {
				return err
			}
			defer v.gate.unlock()
			if !v.started {
				return fmt.Errorf("%w: server has not started", ErrArgument)
			}
			info = map[string]any{"address": v.server.TailcatAddr(), "local_address": v.server.Addr().String(), "public_key": v.server.Key.Public().String()}
		case *listener:
			info = map[string]any{"local_address": v.ln.Addr().String(), "network": v.network}
		case *connection:
			info = map[string]any{"local_address": v.conn.LocalAddr().String(), "remote_address": v.conn.RemoteAddr().String(), "network": v.network}
		default:
			return ErrType
		}
		b, err := json.Marshal(info)
		out = string(b)
		return err
	})
	return
}

func Ping(id, token Handle) (pingMS int32, err error) {
	err = use[*client](id, token, func(ctx context.Context, e *entry, c *client) error {
		r, err := c.client.Ping(ctx)
		if err != nil {
			return err
		}
		c.ready.Store(true)
		pingMS = int32(r.Latency.Milliseconds())
		return nil
	})
	return
}

func DiscoPing(id, token Handle) (out string, err error) {
	err = use[*client](id, token, func(ctx context.Context, e *entry, c *client) error {
		r, err := c.client.DiscoPing(ctx)
		if err != nil {
			return err
		}
		c.ready.Store(true)
		value := map[string]any{"latency": r.LatencySeconds, "endpoint": r.Endpoint, "derp_region_id": r.DERPRegionID, "derp_region_code": r.DERPRegionCode}
		b, err := json.Marshal(value)
		out = string(b)
		return err
	})
	return
}

func AllowClient(id, token Handle, text string) error {
	var pub key.NodePublic
	if err := pub.UnmarshalText([]byte(text)); err != nil || pub.IsZero() {
		return ErrArgument
	}
	return use[*server](id, token, func(ctx context.Context, e *entry, s *server) error {
		if err := s.gate.lock(ctx); err != nil {
			return err
		}
		defer s.gate.unlock()
		if !s.started {
			s.server.AllowedClients = append(s.server.AllowedClients, pub)
		} else {
			s.server.AddAllowedClient(pub)
		}
		return nil
	})
}

func Drain(id, token Handle) error {
	return use[any](id, token, func(ctx context.Context, e *entry, v any) error {
		switch v := v.(type) {
		case *client:
			if !v.ready.Load() {
				return nil
			}
			return v.client.DrainTCP(ctx)
		case *server:
			if err := v.gate.lock(ctx); err != nil {
				return err
			}
			defer v.gate.unlock()
			if !v.started {
				return nil
			}
			return v.server.DrainTCP(ctx)
		default:
			return ErrType
		}
	})
}

func ParseAddress(text string) (string, error) {
	ci, err := tailcat.ParseAddr(tailcat.Addr(text))
	if err != nil {
		return "", fmt.Errorf("%w: invalid tailcat address", ErrArgument)
	}
	// Deliberately omit the pre-shared key from diagnostic metadata.
	b, err := json.Marshal(map[string]any{"public_key": ci.ServerPublic.String(), "disco_public_key": ci.ServerDiscoPublic.String(), "has_preshared_key": !ci.PresharedKey.IsZero(), "region_id": ci.RegionID, "regions": ci.Region})
	return string(b), err
}

func ResolveAddress(token Handle, text, mapURL string) (string, error) {
	if _, err := ParseAddress(text); err != nil {
		return "", err
	}
	ctx, err := tokenContext(token)
	if err != nil {
		return "", err
	}
	var opts []any
	if mapURL != "" {
		opts = append(opts, tailcat.DERPMapURL(mapURL))
	}
	a, err := tailcat.Addr(text).Resolve(ctx, opts...)
	return string(a), err
}

func GenerateKey() (string, error) {
	k := key.NewNode()
	psk, _ := tailcat.NewPresharedKey().MarshalText()
	text, _ := k.MarshalText()
	b, err := json.Marshal(map[string]string{"private_key": string(text), "public_key": k.Public().String(), "preshared_key": string(psk)})
	return string(b), err
}

func BuildInfo() string {
	info, _ := debug.ReadBuildInfo()
	b, _ := json.Marshal(map[string]any{"abi_version": ABIVersion, "go": info})
	return string(b)
}
