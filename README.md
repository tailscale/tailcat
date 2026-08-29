<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

<p align="center"><em>"Tailscale without Tailscale, by Tailscale"</em></p>

# Tailcat

Tailcat is a remix of Tailscale open source pieces to act like
[netcat](https://en.wikipedia.org/wiki/Netcat), but over Tailscale's data plane,
without Tailscale's control plane. Tailscale's data plane (`magicsock`,
internally) gives you point-to-point WireGuard®-encrypted tunnels between two
machines with DERP as the NAT-hole-punching communication side channel and the
ultimate relay-of-last-resort if NAT traversal fails. Instead of using the
Tailscale control plane, all `tailcat` connection metadata is exchanged out of
band, however you want.

The `tailcat` CLI (in `cmd/tailcat`) is built on the `tailcat` Go library
(importable as [`github.com/tailscale/tailcat`](https://pkg.go.dev/github.com/tailscale/tailcat)).

Whether you use `tailcat` as a CLI tool or library, one side runs a `tailcat`
server (listener) and gets back a short connection token. The other side passes
that token to `tailcat`'s client side to connect. All traffic between the two is
encrypted end-to-end with WireGuard. The initial connection bootstraps through
a DERP server ([see below](#bring-your-own-derp-relay)), and then magicsock performs NAT traversal to
upgrade to a direct peer-to-peer UDP connection when possible (usually!).

You don't need a Tailscale account, root/admin access on the machine
(it doesn't alter your machine's routing tables, DNS, etc.). It's just
a userspace library and CLI tool.

And it's all open source.

You can use our free rate-limited DERP relays (the default DERP map is
https://tailcat.dev/derpmap.json) or you can [run your own](https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp).

There's also an experimental in-browser web demo (tailcat compiled to
WebAssembly) at https://tailscale.github.io/tailcat/ that can send and
receive files or text, interoperating with the CLI. Browser traffic is
relayed over DERP only, with no direct connections until WebRTC
support ([#4](https://github.com/tailscale/tailcat/issues/4)).

## Install

```sh
$ go install github.com/tailscale/tailcat/cmd/tailcat@latest
```

Or with Nix flakes, run it directly or install it:

```sh
$ nix run github:tailscale/tailcat
$ nix profile install github:tailscale/tailcat
```

## Usage

### Pipe stdin/stdout between two machines

Server starts, printing out its ephemeral address:
```sh
$ tailcat
# Selected bootstrap relay region 302, San Francisco
# 🐈 Server listening with new address: tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu
(hangs, waiting...)
```

And then the client can:

```sh
$ echo hello | tailcat tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu
$ 
```

Then the server unblocks:

```sh
$ tailcat
# Selected bootstrap relay region 302, San Francisco
# 🐈 Server listening with new address: tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu
hello
$
```

### Expose local ports through the tunnel

Or you can serve a local TCP port, forwarded to localhost:

```sh
$ tailcat --serve=8080,8443 # or --serve=all
# 🐈 Server listening with new address: tcXXXXXXXXX
```

And then the client:

```sh
$ tailcat tcXXXXXXXXX 8080
GET / HTTP/1.1
Host: foo

HTTP/1.1 200 OK
....
```

### Auth-free SSH server

On Linux and macOS, you can run an SSH server too with no auth. (If you want auth, you can just `tailcat --serve=22` and proxy to your system SSH server)

```sh
$ tailcat --serve=no-auth-ssh
# 🐈 Server listening with new address: tcXXXXXXXXX
```

And on the client side:

```sh
$ tailcat ssh tcXXXXXXXXX
$ tailcat ssh tcXXXXXXXXX ls -la
```

### Misc commands 

Ping to test connectivity; each pong reports whether it arrived via a
DERP relay or a direct path. `--until-direct` keeps pinging (up to
`--timeout`, default 10s) until a direct path works, exiting non-zero
if one doesn't:

```sh
$ tailcat ping --until-direct <token>
pong in 42.1ms via DERP(sfo)
pong in 1.2ms via 203.0.113.7:41641
```

Run a command through a SOCKS5 proxy routed over the tunnel:

```sh
$ tailcat socks <token> curl http://server.tailcat:8081/
```

Tokens also work directly as URL hostnames: the SOCKS proxy recognizes
and dials them, so the token argument is optional. (Tokens are
case-sensitive; this works with curl and most CLI tools, but not with
browsers, which lowercase hostnames.)

```sh
$ tailcat socks curl http://<token>:8081/
```

Act as an exit node so the client can reach the server's network:

```sh
$ tailcat --serve=exit-node
```

Parse a connection token and print its contents (the server's WireGuard
public key and DERP info) as JSON, without connecting to anything:

```sh
$ tailcat parse tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu
{
    "ServerPublic": "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34",
    "RegionID": 302
}
```

Resolve a short token (which references a DERP region by ID, requiring
clients to fetch the DERP map) into a longer self-contained one with the
DERP server info embedded, letting clients connect more quickly:

```sh
$ tailcat resolve tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu
tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA
```

Parsing that resolved token shows the embedded DERP info:

```sh
$ tailcat parse tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA
{
    "ServerPublic": "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34",
    "Region": [
        {
            "Nodes": [
                {
                    "HostName": "tc302a.ipn.dev",
                    "IPv4": "208.111.39.38",
                    "IPv6": "2607:f740:0:3f::720"
                }
            ]
        }
    ]
}
```

A server can print the long self-contained form directly with the
`--full-address` flag.

## Key Management

A server's address (connection token) is derived from its WireGuard key, so
the key you use determines who can reach you:

* **Ephemeral keys (the default):** each server run generates a fresh key in
  memory and prints an address nobody has ever seen. When the process exits,
  the key is discarded and the address is dead forever. This is the safe
  default: sharing that address only ever refers to that one run.

* **Saved keys:** `tailcat genkey` generates a key saved to disk so the
  address stays stable across restarts. The flip side: anyone you've *ever*
  shared that address with can connect to any future server using that key,
  unless you restrict clients with `--allow` (see `tailcat genkey --client`).

The CLI says at startup which kind it's using, so you know whether you're
starting a fresh single-use server or re-listening on an address you may
have shared in the past.

```sh
$ tailcat genkey --region=nyc
# prints the token; key saved to ~/.config/tailcat/keys/default.private.json

# later; the key named "default" is used automatically once it exists:
$ tailcat --serve=8080
# 🐈 Server listening with saved key "default": tcXXXXXXXXX

# ... unless you force a one-off ephemeral key:
$ tailcat --serve=8080 --key=new
# 🐈 Server listening with new address: tcXXXXXXXXX
```

That is, `default` is a magic key name: once it exists, plain `tailcat`
silently uses it instead of generating an ephemeral key, and the startup
line above is what tells you which happened. Use `--key=new` to get an
ephemeral key anyway, `--key=<name>` to use a different saved key, or
`tailcat genkey --delete --key=default` to remove the saved default key.
`tailcat genkey --list` lists your saved keys.

Tokens can also be published as DNS TXT records and looked up by name;
a DNS name works anywhere the CLI takes a token:

```sh
# If example.com has a TXT record "tailcat=tc..."
$ tailcat example.com 8080
$ tailcat ssh example.com
$ tailcat ping example.com
```

## Examples

### Protected SSH server over DNS

Who needs port forwarding or port knocking? This runs an SSH server
reachable from anywhere by name, with no open inbound ports on the
server, where WireGuard authenticates the client before the SSH
server ever sees a packet.

On the client machine, generate a client identity keypair. It prints
the public key, which is all the server needs to know:

```sh
client$ tailcat genkey --client
# wrote file to ~/.config/tailcat/keys/client-default.private.json
nodekey:cfb6bfa77a0654d7450947fd6acef17d2cd848da1d30b2540b13dac272ddfd16
```

On the server, generate a server keypair pinned to its nearest DERP
region (see why below), then serve SSH to only that client:

```sh
server$ tailcat genkey --fixed-region
# wrote file to ~/.config/tailcat/keys/default.private.json
tcXXXXXXXXX

server$ tailcat --serve=22 --allow=nodekey:cfb6bf...ddfd16
# 🐈 Server listening with saved key "default": tcXXXXXXXXX
```

Publish the token in DNS as a TXT record:

```
my-server.example.com. 300 IN TXT "tailcat=tcXXXXXXXXX"
```

And then the client side is just:

```sh
client$ tailcat ssh my-server.example.com
```

Client modes automatically use the saved `client-default` key when it
exists, so no extra flags are needed to present the allowed identity.
Anyone else's handshake is silently ignored: they can't reach the SSH
server, or even learn that one is running.

Why `--fixed-region`: it discovers the nearest DERP region once, at
genkey time, and bakes its ID into both the printed token and the
saved key file, so server restarts bind to the same region (keeping
the published token valid) without re-probing. Plain `tailcat genkey`
defaults to `--region=auto`, which instead bakes in "pick at
startup": fine for one-off use, but a token published in DNS should
name a fixed region so clients and future server restarts all
rendezvous in the same place. (`--region=<name>` pins an explicit one
instead; `--region=list` shows the choices.)

TODO: make the client more robust here if the DERP map changes over
time: https://github.com/tailscale/tailcat/issues/7

### Bring your own DERP relay

Nothing requires Tailscale's relays: [run your own DERP
server](https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp)
(it needs a hostname with a TLS certificate, which derper can get
itself via Let's Encrypt), then generate a server key that uses it by
passing its hostname (or several, comma-separated) as the region:

```sh
server$ tailcat genkey --region=derp.example.com
tcomFwWCCAIsKOqPUux6ClG2RM4A_vOq4VBzGgHGGjq9OsJuFKSWFygaFhToGhYWhwZGVycC5leGFtcGxlLmNvbQ

server$ tailcat --serve=22
```

The token embeds your relay's hostname:

```sh
$ tailcat parse tcomFwWCCAIsKOqPUux6ClG2RM4A_vOq4VBzGgHGGjq9OsJuFKSWFygaFhToGhYWhwZGVycC5leGFtcGxlLmNvbQ
{
    "ServerPublic": "nodekey:8022c28ea8f52ec7a0a51b644ce00fef3aae150731a01c61a3abd3ac26e14a49",
    "Region": [
        {
            "Nodes": [
                {
                    "HostName": "derp.example.com"
                }
            ]
        }
    ]
}
```

so clients need no extra flags and never contact Tailscale's DERP map
server or relays, and the only rate limits are yours. Alternatively,
if you run a whole fleet of relays, serve your own DERP map JSON and
point both sides at it with `--derpmap-url`.

### Go library

A minimal server that answers any TCP port through the tunnel and
prints its token. The zero value Server picks defaults for anything
unset: a fresh ephemeral key, the nearest region of the default DERP
map, and `log.Printf` logging (set `Logf` to `logger.Discard` for
quiet):

```go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/tailscale/tailcat"
)

func main() {
	s := &tailcat.Server{
		OnTCP: func(port uint16) func(net.Conn) {
			return func(c net.Conn) {
				fmt.Fprintf(c, "hello from port %v\n", port)
				c.Close()
			}
		},
	}
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
	fmt.Println(s.ConnBlob())
	select {}
}
```

And a minimal client that dials it, given that token as its argument.
Like Server, the Client zero value works with just its Server token
field set (`tailcat.NewClient` is shorthand for exactly that), and
the tunnel is established lazily by the first dial:

```go
package main

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/tailscale/tailcat"
)

func main() {
	cl := tailcat.NewClient(tailcat.ConnBlob(os.Args[1]))
	defer cl.Close()
	c, err := cl.DialTCPPort(context.Background(), 80)
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(os.Stdout, c)
}
```

```sh
$ ./client tcomFwWCAWf933BLELdzd3RkHiOufJ...
hello from port 80
```

## How it works

### Connection tokens

A Tailcat server is identified by a **connection token** (called a
ConnBlob internally). It looks like `tcXYZ...` and is a `"tc"` prefix
followed by base64-encoded [CBOR](https://cbor.io/) containing:

- The server's WireGuard public key (Curve25519, 32 bytes)
- DERP info. Either:
  1. a small integer referencing one of the default [Tailscale-run tailcat servers](https://tailcat.dev/derpmap.json), or
  2. full DERP server metadata, to either use a custom DERP server, or to avoid the client needing a potential round-trip to fetch the latest DERP map (the server's `--full-address` flag and the `tailcat resolve` subcommand produce this form)

A typical token with just an integer region ID is around 50 bytes. With embedded
DERP node details it's longer but self-contained.

### Network stack

Tailcat reuses Tailscale's client networking components but
without the control plane.

- **WireGuard** -- a userspace WireGuard
  implementation for encrypting all tunnel traffic. It doesn't use a kernel TUN/TAP device (nor does it configure any networking routes or DNS settings), so `root` isn't required.
- **magicsock** -- Tailscale's transport layer that multiplexes traffic
  over direct UDP and DERP relays. It handles STUN-based endpoint
  discovery and UDP hole-punching for NAT traversal.
- **Netstack** (gVisor) -- a userspace TCP/IP stack that terminates
  TCP connections inside the process. This is what lets Tailcat
  accept inbound connections and dial outbound ones without any OS
  network configuration.
- **DERP relay** -- Tailscale's encrypted relay protocol, used as a
  rendezvous channel and as a fallback data path when direct
  connectivity isn't possible.

### Connection flow

1. **Server starts.** It generates (or loads) a WireGuard keypair,
   connects to a DERP relay, and prints its connection token to stderr.
   It then waits for clients.

2. **Client parses the token** to learn the server's public key and
   DERP region. It generates its own ephemeral keypair and connects to
   the same DERP relay.

3. **Discovery handshake.** The client sends a "**Meow**" ping message
  to the server through the
   DERP relay. This message carries the client's node public key. The
   server receives it, adds the client to its WireGuard peer list and
   network map, reconfigures the WireGuard engine, and replies with a
   "**Meowed**" acknowledgment.

4. **WireGuard tunnel.** With both sides configured as WireGuard
   peers, the standard WireGuard handshake proceeds (routed through
   DERP initially). Once complete, the tunnel is up and encrypted
   traffic can flow.

5. **NAT traversal.** In parallel, each side advertises its UDP
   endpoints (public IP:port learned via STUN, plus local interface
   addresses) to the other in disco call-me-maybe messages over DERP,
   re-advertising whenever they change. Both sides then run Tailscale's
   disco protocol and attempt UDP hole-punching. If
   successful, traffic upgrades from the DERP relay to a direct
   peer-to-peer path. If hole-punching fails, DERP continues as a
   fallback and the connection still works, just with rate-limited throughput if you're using our public hosted DERP relays.

6. **Data transfer.** The client dials a TCP port on the server
   through the tunnel. gVisor's TCP/IP stack on both sides handles
   connection setup. On the server, the incoming connection is
   dispatched to a handler based on the port: forwarding to localhost,
   piping to stdout, running an SSH session, etc.

### Addressing

Each peer currently derives a deterministic IPv6 address from its WireGuard
public key, but that's an implementation detail not exposed to end users and
might change. (e.g. we might remove those bytes from the IP headers entirely and
recover that redundant MTU)

## Stability

Tailcat is free to use, but it comes with no API or CLI stability
promises: the Go API, the CLI flags and output, and the wire format may
all change. The public rate-limited Tailcat DERP relays have no uptime
SLAs or throughput targets, and we may revoke access to them at any
time, for any reason. Everything is provided best effort, without a
contractual relationship (e.g. dedicated DERP relays and/or support)
saying otherwise.

## Contact Sales?

If you don't want to run and support things on your own, or want any
help, [contact sales](https://tailscale.com/contact/sales) and we can
exchange money for [goods and
services](https://www.youtube.com/watch?v=A81DYZh6KaQ).

## History

Tailcat began life in September 2023 as "derpcat", written on a long
flight while catching up on bad movies: the first sketch was commit
[9e4d925cc](https://github.com/tailscale/tailcat/commit/9e4d925cc)
("cmd/dc: start of derpcat tool"), and it first worked in commit
[911915fbb](https://github.com/tailscale/tailcat/commit/911915fbb)
("derpcat: it's alive!", whose commit message notes "UA 605 PDX-ORD
en route to Ireland. yay not buying the wifi."). Back then it lived
inside a fork of the
[tailscale.com](https://github.com/tailscale/tailscale) repo and it
bitrot several times as the Tailscale internals moved on without it.
We've since brought it back to life and refactored it to be a regular
Go module client of the tailscale.com repo instead of a fork of it.

It was open sourced August 2026 at the
[TailscaleUp conference](https://tailscale.com/tailscaleup).
