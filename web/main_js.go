// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tailcat web app is the WebAssembly (js/wasm) build of tailcat
// for browsers. It exposes two global JavaScript functions,
// tailcatListen and tailcatDial, that app.js uses to implement
// file sharing. The browser reaches DERP relays over WebSockets,
// which tailscale.com's derphttp package does automatically under
// GOOS=js.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	js.Global().Set("tailcatListen", js.FuncOf(tailcatListen))
	js.Global().Set("tailcatDial", js.FuncOf(tailcatDial))
	if f := js.Global().Get("onTailcatReady"); f.Type() == js.TypeFunction {
		f.Invoke()
	}
	select {}
}

// tailcatListen starts a tailcat server in the browser.
//
// It takes one options object argument:
//
//	{
//	  derpMapURL: string,      // absolute URL of the JSON DERP map (required)
//	  privateKey: string,      // optional tailcat.PrivateKey JSON; ephemeral if empty
//	  verbose: bool,           // optional; log to the console
//	  onConnection: (conn) => {}, // called with a conn object per incoming connection
//	}
//
// It returns a Promise that resolves to:
//
//	{
//	  addr: string,           // the "tc..." address to share
//	  privateKeyJSON: string, // the key (with its DERP region pinned), for persistence
//	  close: () => {},
//	}
func tailcatListen(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatListen requires an options object"))
	}
	opts := args[0]
	onConnection := opts.Get("onConnection")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	return makePromise(func() (any, error) {
		if onConnection.Type() != js.TypeFunction {
			return nil, errors.New("onConnection function is required")
		}
		if derpMapURL == "" {
			return nil, errors.New("derpMapURL is required")
		}
		pk := &tailcat.PrivateKey{}
		if keyJSON != "" {
			if err := json.Unmarshal([]byte(keyJSON), pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
		} else {
			pk = tailcat.NewPrivateKey()
			pk.Public.RegionID = -1 // auto-select
		}
		if pk.Public.PresharedKey.IsZero() {
			// Migrate private keys saved by versions predating WireGuard PSKs.
			// The returned privateKeyJSON persists the new address capability.
			pk.Public.PresharedKey = tailcat.NewPresharedKey()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ci := pk.Public
		if err := ci.Expand(ctx, tailcat.ExpandForServer, tailcat.DERPMapURL(derpMapURL)); err != nil {
			return nil, fmt.Errorf("Expand: %w", err)
		}
		reg := ci.Region[0]
		if keyJSON == "" {
			// Pin the picked region so a persisted key keeps the
			// same address across page loads.
			pk.Public.RegionID = reg.RegionID
		}
		addr := pk.Public.Addr()
		keyOut, err := json.Marshal(pk)
		if err != nil {
			return nil, err
		}

		srv := &tailcat.Server{Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Logf: logf, Region: reg}
		srv.OnTCP = func(port uint16) (handler func(net.Conn)) {
			// Like the CLI's default mode, accept a connection on
			// any port and hand it to the page.
			return func(c net.Conn) {
				onConnection.Invoke(makeJSConn(c, port, nil))
			}
		}
		if err := srv.Start(); err != nil {
			srv.Close()
			return nil, fmt.Errorf("Server.Start: %w", err)
		}
		return map[string]any{
			"addr":           string(addr),
			"privateKeyJSON": string(keyOut),
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				srv.Close()
				return nil
			}),
		}, nil
	})
}

// tailcatDial connects to a tailcat server and dials one TCP stream
// over the tunnel.
//
// It takes one options object argument:
//
//	{
//	  addr: string,       // the server's "tc..." address (required)
//	  derpMapURL: string, // optional absolute URL of the JSON DERP map
//	  privateKey: string, // optional tailcat.PrivateKey JSON; ephemeral if empty
//	  port: number,       // optional TCP port; defaults to 1 like the CLI
//	  verbose: bool,
//	}
//
// It returns a Promise that resolves to a conn object (see makeJSConn).
func tailcatDial(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatDial requires an options object"))
	}
	opts := args[0]
	addr := optString(opts, "addr")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	port := uint16(1)
	if p := opts.Get("port"); p.Type() == js.TypeNumber {
		port = uint16(p.Int())
	}
	return makePromise(func() (any, error) {
		if addr == "" {
			return nil, errors.New("addr is required")
		}
		priv := key.NewNode()
		if keyJSON != "" {
			var pk tailcat.PrivateKey
			if err := json.Unmarshal([]byte(keyJSON), &pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
			priv = pk.Private
		}
		cl := &tailcat.Client{
			Server:     tailcat.Addr(addr),
			Key:        priv,
			Logf:       logf,
			DERPMapURL: derpMapURL,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := pingUntil(ctx, cl); err != nil {
			cl.Close()
			return nil, err
		}
		c, err := cl.DialTCPPort(ctx, port)
		if err != nil {
			cl.Close()
			return nil, fmt.Errorf("DialTCPPort: %w", err)
		}
		return makeJSConn(c, port, func() { cl.Close() }), nil
	})
}

// pingUntil retries the meow/meowed handshake until it succeeds or
// ctx expires. The first pings can be lost while either side's DERP
// connection is still coming up.
func pingUntil(ctx context.Context, cl *tailcat.Client) error {
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := cl.Ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("ping: %w", err)
		}
	}
}

// makeJSConn wraps a tunneled TCP connection as a JavaScript object:
//
//	{
//	  port: number,
//	  read: () => Promise<Uint8Array|null>, // null on EOF; no concurrent calls
//	  write: (Uint8Array) => Promise,
//	  closeWrite: () => Promise, // half-close, netcat style
//	  close: () => {},
//	}
//
// read is pull-based: the browser only reads from netstack when the
// page asks for more, so a fast sender stalls on TCP backpressure
// rather than filling browser memory.
func makeJSConn(c net.Conn, port uint16, onClose func()) js.Value {
	buf := make([]byte, 64<<10)
	return js.ValueOf(map[string]any{
		"port": int(port),
		"read": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				n, err := c.Read(buf)
				if n > 0 {
					u8 := js.Global().Get("Uint8Array").New(n)
					js.CopyBytesToJS(u8, buf[:n])
					return u8, nil
				}
				if err == nil || errors.Is(err, io.EOF) {
					return js.Null(), nil
				}
				return nil, err
			})
		}),
		"write": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				return rejectedPromise(errors.New("write requires a Uint8Array"))
			}
			b := make([]byte, args[0].Get("length").Int())
			js.CopyBytesToGo(b, args[0])
			return makePromise(func() (any, error) {
				if _, err := c.Write(b); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"closeWrite": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				cw, ok := c.(interface{ CloseWrite() error })
				if !ok {
					return nil, errors.New("connection does not support half-close")
				}
				if err := cw.CloseWrite(); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			c.Close()
			if onClose != nil {
				onClose()
			}
			return nil
		}),
	})
}

func optString(v js.Value, name string) string {
	if p := v.Get(name); p.Type() == js.TypeString {
		return p.String()
	}
	return ""
}

func optLogf(v js.Value) logger.Logf {
	if v.Get("verbose").Truthy() {
		return log.Printf
	}
	return logger.Discard
}

// makePromise runs f on a new goroutine and returns a JavaScript
// Promise of its result, rejected with a JavaScript Error if f
// returns an error.
func makePromise(f func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			if res, err := f(); err == nil {
				resolve.Invoke(res)
			} else {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
			}
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func rejectedPromise(err error) js.Value {
	return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(err.Error()))
}
