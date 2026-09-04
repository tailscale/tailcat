// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/tailscale/tailcat"
	"go4.org/mem"
	xmaps "golang.org/x/exp/maps"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/socks5"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
)

// The global flags, shared by all subcommands. They're set by
// newRootCommand, which must run before any of them are dereferenced.
var (
	flagServe             *string
	flagKey               *string
	flagAllow             *string
	flagFiles             *string
	flagSSHAuthorizedKeys *string
	flagPSK               *bool
	flagVerbose           *bool
	flagFullAddress       *bool
	flagJSON              *bool
	flagDERPMapURL        *string
)

var serveFS *ff.FlagSet

// The genkey subcommand's flags, likewise set by newRootCommand.
var (
	genkeyFS           *ff.FlagSet
	genkeyKey          *string
	genkeyClient       *bool
	genkeyForce        *bool
	genkeyDelete       *bool
	genkeyList         *bool
	genkeyRegion       *string
	genkeyFixedRegion  *bool
	genkeyEmbedDERPMap *bool
	genkeyPSK          *bool
)

// getLogf returns the logger implied by the --verbose flag.
func getLogf() logger.Logf {
	if *flagVerbose {
		return log.Printf
	}
	return logger.Discard
}

// newRootCommand builds the tailcat command tree. It must only be
// called once per process outside of tests, as it resets the
// package-level flag value pointers.
func newRootCommand() *ff.Command {
	rootFS := ff.NewFlagSet("tailcat")
	flagServe = rootFS.StringLong("serve", "", "comma-separated list of port numbers, port ranges, or service names to serve; the same list the serve subcommand takes as arguments. Service names are: 'all' (serve all ports), 'exit-node' (run an exit node for all addresses), 'ssh' (public-key-authenticated SSH server; see serve's --ssh-authorized-keys flag), 'no-auth-ssh' (auth-free SSH server), 'files' (file server for SFTP clients; see serve's --files flag). If empty, it accepts a single connection on any port, writes it to stdout, and exits.")
	flagKey = rootFS.StringLong("key", "", "'new' for an ephemeral key. If empty, the default saved key is used if it exists ('default' in server mode, 'client-default' in client modes; see genkey), else an ephemeral key. Otherwise the path to a *.private.json or a name like 'foo' to read it from $CONFIG/tailcat/keys/foo.private.json")
	flagVerbose = rootFS.BoolLong("verbose", "be verbose")
	flagJSON = rootFS.BoolLong("json", "in server mode, write {\"listenAddr\": ...} JSON to stdout")
	flagDERPMapURL = rootFS.StringLong("derpmap-url", cmp.Or(os.Getenv("TAILCAT_DERPMAP_URL"), tailcat.DefaultDERPMapURL), "URL of the JSON DERP map used to resolve or auto-select a DERP region; its default can also be set with the TAILCAT_DERPMAP_URL environment variable")

	serveFS = ff.NewFlagSet("serve").SetParent(rootFS)
	flagAllow = serveFS.StringLong("allow", "", "comma-separated list of public keys to allow access to the server, or 'none' to allow no clients. If empty, all clients are allowed.")
	flagFullAddress = serveFS.BoolLong("full-address", "print a longer tailcat address with embedded DERP server info instead of a reference to a DERP map region ID. This lets clients connect more quickly, without a DERP map fetch.")
	flagFiles = serveFS.StringLong("files", "", "directory to serve to SFTP clients (scp, sftp) with the 'files' service, with an optional :ro (read-only, the default), :rw (read-write), :wo (flat write-only drop box), or :wo+ (recursive write-only drop box) suffix. If empty, the current directory is served read-only. Giving --files implies the 'files' service.")
	flagSSHAuthorizedKeys = serveFS.StringLong("ssh-authorized-keys", "", "comma-separated SSH public key sources for the 'ssh' service: authorized_keys file paths, literal OpenSSH public key lines, or names like 'alice@github' (fetched from https://github.com/alice.keys). All sources are loaded and validated at startup.")
	flagPSK = serveFS.BoolLongDefault("psk", true, "include a WireGuard pre-shared key in the tailcat address (recommended). Set false only for shorter addresses and compatibility with tailcat clients v0.5.0 and earlier; this weakens security.")

	recvFS := ff.NewFlagSet("recv").SetParent(serveFS)
	flagRecvAcceptDirs := recvFS.BoolLong("accept-dirs", "accept directory trees (tailcat cp -r), keeping requested file names when available. The trade-off: senders can then make and stat directories and learn whether some names already exist in the drop box. The default flat mode reveals nothing about existing files, but accepts only single files, each saved under a server-chosen unique name.")

	pingFS := ff.NewFlagSet("ping").SetParent(rootFS)
	pingUntilDirect := pingFS.BoolLong("until-direct", "keep pinging until a pong arrives over a direct (non-DERP) path; exit non-zero if that doesn't happen before --timeout")
	pingTimeout := pingFS.DurationLong("timeout", 10*time.Second, "give up after this long")

	socksFS := ff.NewFlagSet("socks").SetParent(rootFS)
	socksListen := socksFS.StringLong("listen", "127.0.0.1:0", "SOCKS5 proxy listen [address]:port; a bare port means localhost, a bare address means an OS-assigned port")

	keysDir := "$CONFIG/tailcat/keys"
	if confDir, err := os.UserConfigDir(); err == nil {
		keysDir = filepath.Join(confDir, "tailcat", "keys")
	}
	genkeyFS = ff.NewFlagSet("genkey").SetParent(rootFS)
	genkeyKey = genkeyFS.StringLong("key", "", "key path (if it contains a slash) or name (written to "+keysDir+"/<name>.private.json). Required. The name 'default' is magic: server mode loads it automatically once it exists. Likewise 'client-default' for client modes.")
	genkeyClient = genkeyFS.BoolLong("client", "generate a client identity key (no DERP region) and print its public key, for use with servers' --allow lists. The 'client-default' key is used automatically by client modes.")
	genkeyForce = genkeyFS.BoolLong("force", "force overwrite of existing key")
	genkeyDelete = genkeyFS.BoolLong("delete", "delete the key named by --key instead of generating one; --key is required and must be a name, not a path")
	genkeyList = genkeyFS.BoolLong("list", "list saved key names and exit")
	genkeyRegion = genkeyFS.StringLong("region", "auto", "region ID, code, or substring to use. Or a hostname(s) comma-separated to use a custom DERP server(s). If 'auto', one is picked based on latency at each server startup. If 'list', list all regions.")
	genkeyFixedRegion = genkeyFS.BoolLong("fixed-region", "discover the nearest DERP region once, now, and bake it into the key and tailcat address, so future server startups (and clients) use it without re-probing")
	genkeyEmbedDERPMap = genkeyFS.BoolLong("embed-derp-map", "embed the DERP map nodes in the tailcat address. Needs a region chosen now, so it implies --fixed-region unless --region names one")
	genkeyPSK = genkeyFS.BoolLongDefault("psk", true, "include a WireGuard pre-shared key in the generated server key and tailcat address (recommended). Set false only for shorter addresses and compatibility with tailcat clients v0.5.0 and earlier; this weakens security.")

	return &ff.Command{
		Name:      "tailcat",
		Usage:     "tailcat [flags] [<subcommand> [flags]] [args...]",
		ShortHelp: "securely pipe or serve network connections over Tailscale's data plane (WireGuard®, NAT traversal), without Tailscale's control plane (central server, accounts)",
		LongHelp:  rootLongHelp,
		Flags:     rootFS,
		Subcommands: []*ff.Command{
			{
				Name:      "serve",
				Usage:     "tailcat serve [flags] [<port,service,...> ...]",
				ShortHelp: "run a server (the default when tailcat is run with no arguments)",
				LongHelp:  serveLongHelp,
				Flags:     serveFS,
				Exec: func(ctx context.Context, args []string) error {
					spec := *flagServe
					if len(args) > 0 {
						if spec != "" {
							return usagef("use either --serve or positional port/service arguments, not both")
						}
						spec = strings.Join(args, ",")
					}
					server(getLogf(), spec)
					return nil
				},
			},
			{
				Name:      "ping",
				Usage:     "tailcat ping [--until-direct] [--timeout=10s] <tc-addr>",
				ShortHelp: "ping a server, reporting DERP or direct paths",
				LongHelp:  pingLongHelp,
				Flags:     pingFS,
				Exec: func(ctx context.Context, args []string) error {
					return clientPingMode(getLogf(), *pingUntilDirect, *pingTimeout, args)
				},
			},
			{
				Name:      "socks",
				Usage:     "tailcat socks [--listen=<addr:port>] [<tc-addr>] [<cmd> [args...]]",
				ShortHelp: "run a SOCKS5 proxy that dials tailcat servers",
				LongHelp:  socksLongHelp,
				Flags:     socksFS,
				Exec: func(ctx context.Context, args []string) error {
					return clientSOCKSMode(getLogf(), *socksListen, args)
				},
			},
			{
				Name:      "recv",
				Usage:     "tailcat recv [flags] [<dir>]",
				ShortHelp: "receive files: serve a directory as a write-only drop box",
				LongHelp:  recvLongHelp,
				Flags:     recvFS,
				Exec: func(ctx context.Context, args []string) error {
					if len(args) > 1 {
						return usagef("recv takes at most one directory argument")
					}
					if *flagFiles != "" {
						return usagef("recv takes the directory as an argument, not --files")
					}
					dir := "."
					if len(args) == 1 {
						dir = args[0]
					}
					mode := ":wo"
					if *flagRecvAcceptDirs {
						mode = ":wo+"
					}
					*flagFiles = dir + mode
					server(getLogf(), "")
					return nil
				},
			},
			sshCommand(rootFS),
			cpCommand(rootFS),
			lsCommand(rootFS),
			forwardCommand(rootFS),
			{
				Name:      "parse",
				Usage:     "tailcat parse <tc-addr>",
				ShortHelp: "decode a tailcat address and print its fields as JSON",
				Exec: func(ctx context.Context, args []string) error {
					return clientParseMode(args)
				},
			},
			{
				Name:      "resolve",
				Usage:     "tailcat resolve <tc-addr>",
				ShortHelp: "expand a short tailcat address to embed its DERP server info",
				Exec: func(ctx context.Context, args []string) error {
					return clientResolveMode(args)
				},
			},
			{
				Name:      "genkey",
				Usage:     "tailcat genkey --key=<name> [--client] [--force] [--list] [--delete]",
				ShortHelp: "generate, list, or delete saved keys",
				LongHelp:  genkeyLongHelp,
				Flags:     genkeyFS,
				Exec: func(ctx context.Context, args []string) error {
					return genKey(args)
				},
			},
			{
				Name:      "printpub",
				Usage:     "tailcat printpub",
				ShortHelp: "print the public key of the client key that would be used",
				Exec: func(ctx context.Context, args []string) error {
					fmt.Println(clientKey().Public().String())
					return nil
				},
			},
			{
				Name:      "version",
				Usage:     "tailcat version",
				ShortHelp: "print the tailcat version",
				Exec: func(ctx context.Context, args []string) error {
					fmt.Println(versionString())
					return nil
				},
			},
			{
				Name:      "readme",
				Usage:     "tailcat readme",
				ShortHelp: "print the tailcat README (documentation with usage examples)",
				Exec: func(ctx context.Context, args []string) error {
					os.Stdout.WriteString(tailcat.README)
					return nil
				},
			},
		},
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 && args[0] == "help" {
				return ff.ErrHelp
			}
			serverMode := len(args) == 0 || *flagServe != ""
			if len(args) > 0 && serverMode {
				return usagef("no positional arguments are valid along with --serve")
			}
			if serverMode {
				server(getLogf(), *flagServe)
				return nil
			}
			if len(args) > 2 {
				return usagef("too many arguments; client mode takes <tc-addr> [<port>]")
			}
			var dst string
			if len(args) == 2 {
				dst = args[1]
			}
			return clientMode(getLogf(), string(tailcatAddrArg(args[0])), dst)
		},
	}
}

const rootLongHelp = `Server mode, accept one connection (any port), write to stdout:

	tailcat

Server mode, given ports (see "tailcat serve --help" for more):

	tailcat serve 22,80,443,8000-8999

Server mode, all ports:

	tailcat serve all

Server mode, certain ports and auth-free SSH:

	tailcat serve 80,no-auth-ssh

Server mode, SSH requiring an authorized public key:

	tailcat serve --ssh-authorized-keys=alice@github ssh

Server mode, exit node (clients can reach the server's whole network):

	tailcat serve exit-node

Server mode, receive files into a directory (a write-only drop box
served to "tailcat cp"; see also serve's files service):

	tailcat recv ~/inbox

Client mode, to default port 1 for stdin/stdout pipe:

	echo hello | tailcat <tc-addr>

Client mode to an explicit port:

	echo "GET / HTTP/1.1..." | tailcat <tc-addr> 80

Anywhere a <tc-addr> argument is accepted, a DNS name whose
"tailcat=" TXT record contains one may be used instead:

	tailcat ssh example.com

Client mode, ping. Each pong reports whether it arrived via a DERP
relay or a direct path. --until-direct keeps pinging (bounded by
--timeout, default 10s) until a direct path works:

	tailcat ping <tc-addr>
	tailcat ping --until-direct <tc-addr>

Client mode, ssh:

	tailcat ssh [user@]<tc-addr>
	tailcat ssh [user@]<tc-addr> <command> [args...]

Client mode, ssh to specific IP:port via the tailcat address's exit node:

	tailcat ssh -p 10.0.0.1:22 <tc-addr>

Client mode, copy files to or from a server (see "tailcat cp --help"
and serve's files service):

	tailcat cp foo.txt <tc-addr>:
	tailcat cp -r <tc-addr>:dir ./dir

Client mode, list the files a server offers:

	tailcat ls [-l] <tc-addr>[:path]

Client mode, forward local TCP ports to a tailcat server:

	tailcat forward [--bind=<addr>] <tc-addr> <[local:]remote> ...

Client mode, run an ephemeral SOCKS5 proxy and pass its address
as 'all_proxy' environment variable to a child process. Destination
hostnames that are themselves tailcat addresses are dialed as tailcat
servers, so the <tc-addr> argument is optional:

	tailcat socks [--listen=<addr:port>] [<tc-addr>] [<cmd> [args...]]
	tailcat socks <tc-addr> curl http://server.tailcat:8081/
	tailcat socks curl http://<tc-addr>:8081/

With no <cmd>, the SOCKS5 proxy server runs by itself and prints
its address.

Parse a tailcat address and print its encoded fields as JSON:

	tailcat parse <tc-addr>

Resolve a short tailcat address into a longer self-contained one with
embedded DERP server info (see also serve's --full-address flag):

	tailcat resolve <tc-addr>

Print the public key of the client key that would be used (see --key):

	tailcat printpub

Generate and save a persistent server key and print its tailcat address
(run "tailcat genkey --help" for its flags). The key name "default"
is magic: server mode uses it automatically once it exists:

	tailcat genkey --key=default

Generate and save a persistent client key and print its public key,
for use in a server's --allow list. Client modes automatically use
the key named "client-default" when it exists:

	tailcat genkey --client --key=client-default

List or delete saved keys:

	tailcat genkey --list
	tailcat genkey --delete --key=<name>

Print the full documentation (the project README) with more examples:

	tailcat readme

Environment:

	TAILCAT_ADDR_FILE: in server mode, write the tailcat address to the
	given file path or, with a "tcp:" prefix, send it to that TCP
	address.

	TAILCAT_DERPMAP_URL: the default value of the --derpmap-url flag.`

const serveLongHelp = `Run a tailcat server, printing its tailcat address for clients to
connect to. Running tailcat with no arguments is the same as running
"tailcat serve" with no arguments.

The arguments are port numbers, port ranges, and service names,
either as separate arguments or comma-separated. Ports are proxied
to the same port on localhost. Service names are:

	all          serve all ports
	exit-node    run an exit node for all addresses
	ssh          SSH server requiring a public key listed by
	             --ssh-authorized-keys
	no-auth-ssh  auth-free SSH server (the tunnel provides identity;
	             the served process gets the peer's node key in
	             $TAILCAT_PEER_KEY)
	files        file server for SFTP clients like scp and sftp,
	             rooted in the --files directory (default: the
	             current directory, read-only)

With no arguments, the server accepts a single connection on any
port, writes it to stdout, and exits.

Flags must come before the port and service arguments.

Accept one connection, write it to stdout:

	tailcat serve

Serve some ports:

	tailcat serve 22,80,443,8000-8999

Serve all ports:

	tailcat serve all

Serve a port and the auth-free SSH server:

	tailcat serve 80,no-auth-ssh

Serve SSH, trusting public keys fetched from GitHub at startup:

	tailcat serve --ssh-authorized-keys=alice@github ssh

Serve SSH, trusting keys from files and a literal public key:

	tailcat serve --ssh-authorized-keys="$HOME/.ssh/authorized_keys,ssh-ed25519 AAAA..." ssh

Run an exit node (clients can reach the server's whole network):

	tailcat serve exit-node

Serve the current directory read-only to scp and sftp clients:

	tailcat serve files

Serve a directory read-write, as a flat write-only drop box, or as a
recursive write-only drop box:

	tailcat serve --files=/pub:rw files
	tailcat serve --files=/inbox:wo files
	tailcat serve --files=/tree-inbox:wo+ files

Serve with a saved key (see genkey) and restrict clients:

	tailcat serve --key=default --allow=nodekey:... 22

Environment:

	TAILCAT_ADDR_FILE: write the tailcat address to the given file
	path or, with a "tcp:" prefix, send it to that TCP address.`

const recvLongHelp = `Run a server that receives files into the given directory (default:
the current directory), printing the tailcat address senders use. It's
shorthand for a write-only file server:

	tailcat serve --files=<dir>:wo files

The sender copies files in with (see "tailcat cp --help"):

	tailcat cp foo.txt <tc-addr>:

Write-only means senders can't make directories, list or read the
directory, touch existing files, or learn whether a requested filename
already exists. Each upload is saved under a new name containing a UTC
timestamp and random suffix, so the tailcat address only grants dropping
files off. To accept directory trees instead, use the less-private
--accept-dirs flag; see its description for the trade-off.

Receive into the current directory, or into a given one:

	tailcat recv
	tailcat recv ~/inbox`

const pingLongHelp = `Examples:

	tailcat ping <tc-addr>
	tailcat ping --until-direct <tc-addr>
	tailcat ping --until-direct --timeout=30s <tc-addr>

Each pong reports whether it arrived via a DERP relay or a direct
path:

	pong in 42.1ms via DERP(sfo)
	pong in 1.2ms via 203.0.113.7:41641

The --until-direct flag keeps pinging (bounded by --timeout) until a
direct path works, exiting non-zero if none does, so scripts can use
it to verify NAT traversal.`

const socksLongHelp = `Examples:

	tailcat socks
	tailcat socks <tc-addr>
	tailcat socks --listen=1080 <tc-addr>
	tailcat socks curl http://<tc-addr>:8081/
	tailcat socks <tc-addr> curl http://server.tailcat:8081/
	tailcat socks <tc-addr> curl https://example.com/

With a <cmd>, the SOCKS5 proxy runs for the life of that command,
which is started with the proxy's address in its all_proxy
environment variable (respected by curl and most CLI tools). With no
<cmd>, the proxy runs by itself and prints its address.

The proxy routes each connection by its destination hostname:

A hostname that is itself a tailcat address names a tailcat server to
dial, so addrs work directly in URLs and the <tc-addr> argument
isn't needed. (Addrs are case-sensitive; this works with CLI tools
but not with browsers, which lowercase hostnames.)

The magic hostname "server.tailcat" means the server named by the
<tc-addr> argument.

Any other hostname or IP is reached through the <tc-addr> server
acting as an exit node, which works only if the server runs with
--serve=exit-node.

The --listen flag sets the proxy's listen address: a bare port means
localhost on that port, a bare address means an OS-assigned port,
and an empty host (as in ":1080") means all interfaces.`

const genkeyLongHelp = `Examples:

	tailcat genkey --key=default
	tailcat genkey --client --key=client-default
	tailcat genkey --key=default --fixed-region
	tailcat genkey --key=default --region=nyc
	tailcat genkey --key=default --region=derp.example.com
	tailcat genkey --region=list
	tailcat genkey --list
	tailcat genkey --delete --key=<name>

By default genkey generates and saves a server key and prints its
tailcat address. The key name "default" is magic: server mode loads it
automatically once it exists. Any other name works too, named at
serve time with --key=<name>, to keep multiple identities.

With --client, genkey generates a client identity key and prints its
public key, for use in a server's --allow list. Client modes
automatically load the magic name "client-default" once it exists.

A server key normally picks its DERP relay region by latency at each
server startup (--region=auto). The --region and --fixed-region
flags bake a region into the key and its tailcat address instead; a
tailcat address published in DNS should do that, so clients and future
server restarts all rendezvous in the same place. --region takes a
region ID, code, or name substring ("list" prints the choices), or
one or more comma-separated DERP server hostnames to use relays that
aren't in the DERP map at all.`

// version is set via -ldflags by GoReleaser at release time.
// It is empty for go-install and plain go-build builds.
var version string

// versionString returns the version set at release build time,
// falling back to the module version from the Go build info.
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "unknown"
}

// usageError is an error caused by bad command line usage, as opposed
// to a failure doing the requested work. main prints the selected
// command's full help text along with it.
type usageError struct{ error }

// usagef returns a usageError whose message is the given
// fmt.Sprintf-style arguments.
func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

func main() {
	root := newRootCommand()
	err := root.Parse(os.Args[1:])
	if err != nil && slices.Contains(os.Args[1:], "--version") {
		// The advertised way to get the version is the version
		// subcommand, but nixpkgs' versionCheckHook runs "tailcat
		// --version", so keep that working as an unadvertised alias.
		// It's not a registered flag, so it only shows up here as a
		// parse failure.
		fmt.Println(versionString())
		return
	}
	if err == nil {
		if *flagVerbose {
			tailcat.Verbose = true
		}
		err = root.Run(context.Background())
	}
	if err == nil {
		return
	}
	if errors.Is(err, ff.ErrHelp) {
		// Explicitly requested help goes to stdout, so it can be
		// piped into a pager. ffhelp.Command renders help for the
		// subcommand selected during the parse, or for the root
		// command if none was.
		ffhelp.Command(root).WriteTo(os.Stdout)
		os.Exit(0)
	}
	// A trailing --serve with no value is almost certainly someone
	// asking what serving does, and ff's "missing value" error names
	// neither the flag nor a fix. Treat it as a request for the serve
	// subcommand's help. (A missing flag value can only be at the end
	// of the arguments, so checking the last one suffices.)
	if strings.Contains(err.Error(), "missing value") && os.Args[len(os.Args)-1] == "--serve" {
		for _, sub := range root.Subcommands {
			if sub.Name == "serve" {
				ffhelp.Command(sub).WriteTo(os.Stdout)
				os.Exit(0)
			}
		}
	}
	// Usage errors (including unknown flags) get the same help text
	// as "tailcat <cmd> --help", with the error last, where it's
	// visible under the scrollback.
	var ue usageError
	if errors.As(err, &ue) || errors.Is(err, ff.ErrUnknownFlag) {
		ffhelp.Command(root).WriteTo(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}
	// No "tailcat:" prefix here: ff's parse errors already carry the
	// command name, and exec errors read fine bare.
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// tailcatAddrArg interprets a CLI destination argument as either a
// "tc"-prefixed tailcat address or a DNS name whose "tailcat=" TXT
// record holds one. It exits the process on failure.
func tailcatAddrArg(arg string) tailcat.Addr {
	addr, dnsName, err := classifyTailcatAddrArg(arg)
	if err != nil {
		log.Fatal(err)
	}
	if dnsName != "" {
		var r net.Resolver
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		txts, err := r.LookupTXT(ctx, dnsName)
		if err != nil {
			log.Fatalf("looking up TXT record for %q: %v", dnsName, err)
		}
		for _, txt := range txts {
			if suf, ok := strings.CutPrefix(txt, "tailcat="); ok {
				return tailcat.Addr(strings.TrimSpace(suf))
			}
		}
		log.Fatalf("no \"tailcat=\" TXT record found for %q", dnsName)
	}
	return addr
}

// classifyTailcatAddrArg classifies arg without performing a DNS lookup. It
// rejects DNS-looking input containing a valid tailcat address as a label so
// that pasting an address with an adjacent period or other dotted suffix cannot
// disclose the address in a DNS query.
func classifyTailcatAddrArg(arg string) (addr tailcat.Addr, dnsName string, err error) {
	addr = tailcat.Addr(arg)
	if _, err := tailcat.ParseAddr(addr); err == nil {
		return addr, "", nil
	}
	if !strings.Contains(arg, ".") {
		return "", "", fmt.Errorf("argument %q is neither a valid tailcat address nor a DNS name", arg)
	}

	name := strings.TrimSuffix(arg, ".")
	for label := range strings.SplitSeq(name, ".") {
		if _, err := tailcat.ParseAddr(tailcat.Addr(label)); err == nil {
			return "", "", errors.New("argument contains a valid tailcat address as a DNS label; refusing DNS lookup")
		}
	}
	if err := validateDNSName(name); err != nil {
		return "", "", fmt.Errorf("invalid DNS name %q: %w", arg, err)
	}
	return "", arg, nil
}

// validateDNSName validates the conservative ASCII hostname syntax accepted
// for tailcat address TXT lookups.
func validateDNSName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > 253 {
		return errors.New("name is longer than 253 bytes")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return errors.New("name contains an empty label")
		}
		if len(label) > 63 {
			return errors.New("name contains a label longer than 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("name contains a label beginning or ending with a hyphen")
		}
		for _, c := range []byte(label) {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return fmt.Errorf("name contains invalid character %q", c)
		}
	}
	return nil
}

func clientKey() key.NodePrivate {
	if *flagKey == "" {
		path := keyPath("client-default")
		if _, err := os.Stat(path); err == nil {
			*flagKey = "client-default"
		} else {
			return key.NewNode()
		}
	}
	if *flagKey == "new" {
		return key.NewNode()
	}
	path := keyPath(*flagKey)
	j, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(j, &conf); err != nil {
		log.Fatalf("failed to parse %v: %v", path, err)
	}
	return conf.Private
}

// newClient returns a [tailcat.Client] configured with the global
// --derpmap-url flag and the disk DERP map cache.
func newClient(logf logger.Logf, addr tailcat.Addr, priv key.NodePrivate) *tailcat.Client {
	return &tailcat.Client{
		Server:       addr,
		Key:          priv,
		Logf:         logf,
		DERPMapURL:   *flagDERPMapURL,
		DERPMapCache: derpMapCache{},
	}
}

// derpMapCache implements [tailcat.DERPMapCache] on disk, in
// $XDG_CACHE_HOME/tailcat (~/.cache/tailcat on Linux). Each DERP map
// URL gets a derpmap-<url-escaped-URL>.json file whose mtime is the
// stored-at time, with the server's ETag in a parallel *.etag file.
type derpMapCache struct{}

func (derpMapCache) paths(url string) (dataPath, etagPath string, err error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(dir, "tailcat", "derpmap-"+neturl.QueryEscape(url))
	return base + ".json", base + ".etag", nil
}

func (c derpMapCache) Get(url string) (data []byte, etag string, storedAt time.Time, ok bool) {
	dataPath, etagPath, err := c.paths(url)
	if err != nil {
		return
	}
	fi, err := os.Stat(dataPath)
	if err != nil {
		return
	}
	data, err = os.ReadFile(dataPath)
	if err != nil {
		return
	}
	if v, err := os.ReadFile(etagPath); err == nil {
		etag = strings.TrimSpace(string(v))
	}
	return data, etag, fi.ModTime(), true
}

func (c derpMapCache) Put(url string, data []byte, etag string) error {
	dataPath, etagPath, err := c.paths(url)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dataPath), 0700); err != nil {
		return err
	}
	// Rewriting the same contents still bumps the mtime, restarting
	// the freshness window after a 304 revalidation.
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		return err
	}
	if etag == "" {
		os.Remove(etagPath)
		return nil
	}
	return os.WriteFile(etagPath, []byte(etag), 0644)
}

func clientPingMode(logf logger.Logf, untilDirect bool, timeout time.Duration, args []string) error {
	if len(args) != 1 {
		return usagef("ping requires one <tc-addr> argument")
	}
	cl := newClient(logf, tailcatAddrArg(args[0]), clientKey())
	defer cl.Close()

	deadline := time.Now().Add(timeout)
	for {
		t0 := time.Now()
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		res, err := cl.DiscoPing(ctx)
		cancel()
		if err != nil {
			if untilDirect && errors.Is(err, context.DeadlineExceeded) {
				log.Fatalf("no direct path to the server after %v", timeout)
			}
			log.Fatalf("ping: %v", err)
		}
		latency := time.Duration(res.LatencySeconds * float64(time.Second)).Round(10 * time.Microsecond)
		direct := res.Endpoint != ""
		via := res.Endpoint
		if !direct {
			via = fmt.Sprintf("DERP(%v)", cmp.Or(res.DERPRegionCode, res.DERPRegionID.String()))
		}
		fmt.Printf("pong in %v via %v\n", latency, via)
		if direct || !untilDirect {
			return nil
		}
		if time.Until(deadline) < time.Second/2 {
			log.Fatalf("no direct path to the server after %v", timeout)
		}
		time.Sleep(max(0, time.Second-time.Since(t0)))
	}
}

func clientMode(logf logger.Logf, connStr, optDest string) error {
	cl := newClient(logf, tailcat.Addr(connStr), clientKey())

	var dial func(context.Context) (net.Conn, error)
	switch {
	case optDest == "":
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, 1) }
	case !strings.Contains(optDest, ":"):
		port, err := strconv.ParseUint(optDest, 10, 16)
		if err != nil {
			return usagef("invalid port number %q", optDest)
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, uint16(port)) }
	default:
		addrPort, err := netip.ParseAddrPort(optDest)
		if err != nil {
			return usagef("invalid IP:port %q", optDest)
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCP(ctx, addrPort) }
	}

	pi, err := cl.Ping(context.Background())
	if err != nil {
		log.Fatalf("tailcat Ping: %v", err)
	}
	if *flagVerbose {
		logf("got ping: %+v", pi)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	go func() {
		_, err := io.Copy(c, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		// Half-close: tell the server we're done sending so it can
		// respond to a complete request, netcat style.
		if err := c.(*gonet.TCPConn).CloseWrite(); err != nil {
			log.Fatal(err)
		}
	}()

	// Exit when the server finishes sending. Its close also confirms
	// delivery of everything we sent, including the half-close FIN
	// above: the whole network stack is in this userspace process, so
	// there's no kernel to flush unsent packets after we exit, and
	// exiting earlier (as this code once did, after a hopeful sleep)
	// can lose data in flight in either direction.
	if _, err := io.Copy(os.Stdout, c); err != nil {
		log.Fatal(err)
	}

	// The EOF above means the server closed. Our netstack acks its
	// FIN, but the ack starts in this process and exiting right away
	// can discard it before it's transmitted, leaving the server
	// retransmitting its FIN to nobody until it gives up. Wait for
	// the ack to drain, with a cap in case the server is gone.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	cl.DrainTCP(drainCtx)
	return nil
}

// normalizeListenAddrPort fills in the missing parts of the --listen
// flag value s so it's a valid net.Listen address. A bare port means
// localhost on that port; a bare host means an OS-assigned port; an
// empty host (as in ":1234") is left alone, meaning all interfaces.
// It doesn't validate the result, leaving that to net.Listen.
func normalizeListenAddrPort(s string) string {
	if host, port, err := net.SplitHostPort(s); err == nil {
		if port == "" {
			port = "0"
		}
		return net.JoinHostPort(host, port)
	} else if port, err := strconv.ParseUint(s, 10, 16); err == nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	}
	// Assume it's a hostname or IP without a port.
	return s + ":0"
}

func clientSOCKSMode(logf logger.Logf, listen string, args []string) error {
	listenAddrPort := normalizeListenAddrPort(listen)

	// The tailcat address argument is optional: destination hostnames that
	// are themselves tailcat addresses are dialed directly (see
	// classifySOCKSAddr), so a fixed server is only needed for the
	// server.tailcat magic name and exit-node destinations.
	var addr tailcat.Addr
	if len(args) > 0 {
		if _, err := tailcat.ParseAddr(tailcat.Addr(args[0])); err == nil {
			addr = tailcat.Addr(args[0])
			args = args[1:]
		} else if strings.Contains(args[0], ".") {
			if _, err := exec.LookPath(args[0]); err != nil {
				// Not a runnable command, so treat it as a DNS name
				// holding a tailcat address in a TXT record.
				addr = tailcatAddrArg(args[0])
				args = args[1:]
			}
		}
	}
	progArgs := args

	// Resolve the client key once so every server dialed by this
	// proxy sees the same identity, matching the other client modes.
	clientPriv := clientKey()

	var cl *tailcat.Client
	if addr != "" {
		cl = newClient(logf, addr, clientPriv)
		pi, err := cl.Ping(context.Background())
		if err != nil {
			log.Fatalf("tailcat Ping: %v", err)
		}
		logf("got ping: %+v", pi)
	}

	var clientsMu sync.Mutex
	clients := map[tailcat.Addr]*tailcat.Client{}
	if cl != nil {
		clients[addr] = cl
	}
	clientForAddr := func(b tailcat.Addr) *tailcat.Client {
		clientsMu.Lock()
		defer clientsMu.Unlock()
		if c, ok := clients[b]; ok {
			return c
		}
		c := newClient(logf, b, clientPriv)
		clients[b] = c
		return c
	}

	socksLn, err := net.Listen("tcp", listenAddrPort)
	if err != nil {
		log.Fatal(err)
	}
	ss := &socks5.Server{
		Logf: logger.WithPrefix(logf, "socks5: "),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The socks5 package caps each dial at 5 seconds, which
			// is also WireGuard's handshake retransmit interval, so
			// a single lost handshake packet would push the dial
			// past that budget and fail the CONNECT. Detach from the
			// package's deadline and use a more generous one.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			dst, err := classifySOCKSAddr(ctx, lookupNetIP, addr)
			if err != nil {
				return nil, err
			}
			return dialSOCKSTarget(ctx, network, dst, cl, clientForAddr)
		},
	}
	socksAddr := "socks5h://" + socksLn.Addr().String()
	if len(progArgs) > 0 {
		go func() {
			log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksLn))
		}()
		logf("SOCKS running at %v", socksAddr)
		cmd := exec.Command(progArgs[0], progArgs[1:]...)
		cmd.Env = append(os.Environ(),
			"all_proxy="+socksAddr,
		)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("SOCKS running at %v", socksAddr)
		log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksLn))
	}
	return nil
}

// dialSOCKSTarget dials a classified SOCKS destination over the tailcat
// tunnel. UDP ASSOCIATE targets (network == "udp") use the connected packet
// connections from [tailcat.Client.DialUDPPort] and [tailcat.Client.DialUDP],
// which satisfy net.Conn with datagram-preserving Read/Write as the SOCKS5
// UDP relay expects; everything else dials TCP as before.
func dialSOCKSTarget(ctx context.Context, network string, dst socksTarget, cl *tailcat.Client, clientForAddr func(tailcat.Addr) *tailcat.Client) (net.Conn, error) {
	if network == "udp" {
		if dst.addr != "" {
			return clientForAddr(dst.addr).DialUDPPort(ctx, dst.port)
		}
		if cl == nil {
			return nil, errors.New("no tailcat address argument was given to \"tailcat socks\"; only tailcat address hostnames can be dialed")
		}
		if dst.toServer {
			return cl.DialUDPPort(ctx, dst.port)
		}
		return cl.DialUDP(ctx, dst.dst)
	}
	if dst.addr != "" {
		return clientForAddr(dst.addr).DialTCPPort(ctx, dst.port)
	}
	if cl == nil {
		return nil, errors.New("no tailcat address argument was given to \"tailcat socks\"; only tailcat address hostnames can be dialed")
	}
	if dst.toServer {
		return cl.DialTCPPort(ctx, dst.port)
	}
	return cl.DialTCP(ctx, dst.dst)
}

// socksTarget is where a SOCKS5 destination address should be dialed.
type socksTarget struct {
	toServer bool           // dial the tailcat server from the command line
	addr     tailcat.Addr   // if non-empty, the tailcat address hostname to dial
	port     uint16         // the port to dial, if toServer or addr is set
	dst      netip.AddrPort // the IP:port to dial through the server as an exit node, otherwise
}

// lookupNetIP resolves host using the local resolver, for
// [classifySOCKSAddr].
func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// classifySOCKSAddr decides where the SOCKS5 destination address should be
// dialed. The magic hostname "server.tailcat" (or an empty host) means the
// tailcat server itself. A hostname that is a valid tailcat address (which can
// never contain a dot) means the server that address names, letting addresses be
// used directly in URLs. IP literals and hostnames resolved with lookup are
// reached through the server acting as an exit node, preferring IPv4
// addresses because they ride the NAT64 mapping and the server may not have
// IPv6 connectivity.
func classifySOCKSAddr(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), addr string) (socksTarget, error) {
	var zero socksTarget
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return zero, err
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return zero, err
	}
	if host == "server.tailcat" || host == "" {
		return socksTarget{toServer: true, port: uint16(portNum)}, nil
	}
	if strings.HasPrefix(host, "tc") && !strings.Contains(host, ".") {
		if _, err := tailcat.ParseAddr(tailcat.Addr(host)); err == nil {
			return socksTarget{addr: tailcat.Addr(host), port: uint16(portNum)}, nil
		}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := lookup(ctx, host)
		if err != nil {
			return zero, err
		}
		if len(ips) == 0 {
			return zero, fmt.Errorf("no addresses found for %q", host)
		}
		ip = ips[0]
		for _, a := range ips {
			if a.Unmap().Is4() {
				ip = a
				break
			}
		}
	}
	return socksTarget{dst: netip.AddrPortFrom(ip.Unmap(), uint16(portNum))}, nil
}

func clientParseMode(args []string) error {
	if len(args) != 1 {
		return usagef("parse requires one <tc-addr> argument")
	}
	v, err := tailcat.ParseAddrRaw(tailcat.Addr(args[0]))
	if err != nil {
		return err
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "    ")
	return e.Encode(v)
}

func clientResolveMode(args []string) error {
	if len(args) != 1 {
		return usagef("resolve requires one <tc-addr> argument")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := tailcatAddrArg(args[0]).Resolve(ctx, tailcat.DERPMapURL(*flagDERPMapURL), derpMapCache{})
	if err != nil {
		return err
	}
	fmt.Println(resolved)
	return nil
}

func server(logf logger.Logf, serveSpec string) {
	portSet, services, err := parsePortSet(serveSpec)
	if err != nil {
		log.Fatalf("invalid port or service to serve: %v", err)
	}
	if *flagFiles != "" {
		if !tailCatSSHEnabled {
			log.Fatalf("--files requires SSH support, not included in binary per build tags")
		}
		if services == nil {
			services = set.Set[string]{}
		}
		services.Add("files")
	}
	sshWithAuth := services.Contains("ssh")
	sshWithoutAuth := services.Contains("no-auth-ssh")
	if sshWithAuth && sshWithoutAuth {
		log.Fatal("the 'ssh' and 'no-auth-ssh' services cannot be served together")
	}
	if sshWithAuth && *flagSSHAuthorizedKeys == "" {
		log.Fatal("the 'ssh' service requires --ssh-authorized-keys")
	}
	if sshWithoutAuth && *flagSSHAuthorizedKeys != "" {
		log.Fatal("--ssh-authorized-keys cannot be used with the 'no-auth-ssh' service; use 'ssh' instead")
	}
	if *flagSSHAuthorizedKeys != "" && !sshWithAuth {
		log.Fatal("--ssh-authorized-keys requires the 'ssh' service")
	}
	var sshAuthorizedKeys []string
	if *flagSSHAuthorizedKeys != "" {
		if !tailCatSSHEnabled {
			log.Fatal("--ssh-authorized-keys requires SSH support, not included in binary per build tags")
		}
		sshAuthorizedKeys, err = loadSSHAuthorizedKeys(context.Background(), *flagSSHAuthorizedKeys)
		if err != nil {
			log.Fatalf("--ssh-authorized-keys: %v", err)
		}
	}
	// A server running only named services isn't the empty-port-list
	// accept-one-connection stdout mode.
	oneShotStdout := len(portSet) == 0 && len(services) == 0

	var reg *tailcfg.DERPRegion
	var devDERP *derpserver.Server
	if envknob.Bool("TS_DEBUG_TAILCAT_LOCAL_DERP") {
		log.Printf("Local DERP mode.")
		devDERP, reg = runDevDERP(logger.WithPrefix(logf, "[dev-derp] "))
	}

	var priv key.NodePrivate
	var ci *tailcat.ConnInfo
	pskFlag, ok := serveFS.GetFlag("psk")
	if !ok {
		panic("serve flag set has no psk flag")
	}
	usePSK := *flagPSK

	if *flagKey == "" {
		if _, err := os.Stat(keyPath("default")); err == nil {
			*flagKey = "default"
		} else if os.IsNotExist(err) {
			*flagKey = "new"
		} else {
			log.Fatalf("failed to stat default key: %v", err)
		}
	}
	if *flagKey == "new" {
		conf := tailcat.NewPrivateKey()
		priv = conf.Private
		ci = &conf.Public
		ci.RegionID = -1 // auto-detect
	} else {
		path := keyPath(*flagKey)
		j, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		var conf tailcat.PrivateKey
		if err := json.Unmarshal(j, &conf); err != nil {
			log.Fatalf("failed to parse %v: %v", path, err)
		}
		priv = conf.Private
		ci = &conf.Public
		if ci.PresharedKey.IsZero() && !pskFlag.IsSet() {
			// Saved keys remember whether they use a PSK, so a key made with
			// genkey --psk=false needs no corresponding serve flag.
			usePSK = false
		}
		if usePSK && ci.PresharedKey.IsZero() {
			log.Fatalf("key file %v has no WireGuard pre-shared key", path)
		}
	}
	if !usePSK {
		ci.PresharedKey = tailcat.PresharedKey{}
	}
	psk := ci.PresharedKey
	if reg == nil {
		// A key created with custom DERP hostnames (genkey --region=<host>)
		// has pre-populated regions with no DERP map ID to reference, so its
		// address always embeds the DERP info. Decide before Expand, which
		// zeroes RegionID when it populates Region.
		embed := *flagFullAddress || len(ci.Region) > 0

		if err := ci.Expand(context.Background(), tailcat.ExpandForServer, tailcat.DERPMapURL(*flagDERPMapURL), derpMapCache{}); err != nil {
			log.Fatalf("Expand: %v", err)
		}
		reg = ci.Region[0]
		clearUnnecessaryRegionFields(reg)
		fmt.Fprintf(os.Stderr, "# Selected bootstrap relay region %v, %v\n", reg.RegionID, reg.RegionName)

		ci = &tailcat.ConnInfo{PresharedKey: psk}
		if embed {
			ci.Region = []*tailcfg.DERPRegion{reg}
		} else {
			ci.RegionID = reg.RegionID
		}
	} else {
		// The local dev DERP region has no public DERP map region ID
		// to reference, so the address must embed it.
		ci = &tailcat.ConnInfo{
			ServerPublic: tailcat.NodePublic{NodePublic: priv.Public()},
			PresharedKey: psk,
			Region:       []*tailcfg.DERPRegion{reg},
		}
	}
	ci.ServerPublic = tailcat.NodePublic{NodePublic: priv.Public()}
	ci.ServerDiscoPublic = tailcat.DiscoPublicForNode(priv)
	connStr := ci.Addr()

	s := &tailcat.Server{Key: priv, PresharedKey: psk, DisablePresharedKey: !usePSK, Logf: logf, Region: reg}
	sshServices := services.Contains("ssh") || services.Contains("no-auth-ssh") || services.Contains("files")
	if sshServices && !tailcat.SupportsSSHServer() {
		log.Fatalf("Tailscale SSH server not supported on %v", runtime.GOOS)
	}
	// Outside the accept-one-connection stdout mode (and exit-node
	// mode, which accepts any port), tighten the packet filter to just
	// the served ports for defense in depth behind the OnTCP gate.
	if !oneShotStdout && !services.Contains("exit-node") {
		ports := slices.Sorted(maps.Keys(portSet))
		if sshServices && !portSet.Contains(22) {
			ports = append([]uint16{22}, ports...)
		}
		s.ServedTCPPorts = portRanges(ports)
	}
	if *flagAllow != "" {
		for _, ks := range strings.Split(*flagAllow, ",") {
			if ks == "none" {
				s.AddAllowedClient(key.NodePublic{})
				continue
			}
			var k key.NodePublic
			if err := k.UnmarshalText([]byte(ks)); err != nil {
				log.Fatalf("invalid key %q in --allow: %v", ks, err)
			}
			s.AddAllowedClient(k)
		}
	}

	tcpForwardTo := func(ipPortStr string) func(net.Conn) {
		return func(c net.Conn) {
			localConn, err := net.Dial("tcp", ipPortStr)
			if err != nil {
				logf("error proxying to %v: %v", ipPortStr, err)
				c.Close()
				return
			}
			tailcat.ProxyConns(c, localConn)
		}
	}

	if services.Contains("exit-node") {
		s.OnTCPForward = func(dst netip.AddrPort) (handler func(net.Conn)) {
			return tcpForwardTo(dst.String())
		}
	}

	var sshHandler func(net.Conn)
	if sshServices {
		opts := tailcat.SSHOptions{
			Shell:          services.Contains("ssh") || services.Contains("no-auth-ssh"),
			AuthorizedKeys: sshAuthorizedKeys,
		}
		if services.Contains("files") {
			fsrv, modeName, err := parseFilesFlag(*flagFiles)
			if err != nil {
				log.Fatal(err)
			}
			opts.Files = fsrv
			fmt.Fprintf(os.Stderr, "# Serving files from %v (%v)\n", fsrv.Dir, modeName)
		}
		sshHandler = s.SSHConnHandler(opts)
	}

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if port == 22 && sshHandler != nil {
			return sshHandler
		}
		if services.Contains("exit-node") {
			// Being an exit node includes localhost without needing
			// to specify all the local port ranges.
			return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
		}
		if oneShotStdout {
			return func(c net.Conn) {
				_, err := io.Copy(os.Stdout, c)
				if err != nil {
					log.Fatal(err)
				}
				// Close stdout now so anything downstream in a
				// pipeline sees EOF without waiting for the drain
				// below.
				os.Stdout.Close()
				c.Close()
				// The client exits only once it reads our EOF, which
				// confirms delivery of everything it sent (see
				// clientMode). The whole TCP stack runs in this
				// process, so exiting now could discard the FIN
				// queued by the Close above and leave the client
				// hanging. Wait until the client acks it, with a cap
				// in case the client is gone.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				s.DrainTCP(ctx)
				os.Exit(0)
			}
		}
		if !portSet.Contains(port) {
			return nil // RST
		}
		return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
	}

	if err := s.Start(); err != nil {
		log.Fatalf("Server.Start: %v", err)
	}
	if psk.IsZero() {
		if *flagKey == "new" {
			fmt.Fprintln(os.Stderr, "# ⚠️ WARNING: serving without a WireGuard PSK")
		} else {
			fmt.Fprintf(os.Stderr, "# ⚠️ WARNING: saved key %q is not using a WireGuard PSK\n", *flagKey)
		}
	}
	if devDERP != nil {
		// Wait until we're connected to our own dev DERP before
		// publishing the address, so a client that acts on it
		// immediately can reach us. Without this, the client's first
		// packets get dropped by the relay and tests get slow or
		// flaky waiting for retransmits.
		deadline := time.Now().Add(30 * time.Second)
		for !devDERP.IsClientConnectedForTest(priv.Public()) {
			if time.Now().After(deadline) {
				log.Fatalf("timeout waiting for connection to local dev DERP")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if *flagKey == "new" {
		fmt.Fprintf(os.Stderr, "# 🐈 Server listening with new address: %v\n", connStr)
	} else {
		fmt.Fprintf(os.Stderr, "# 🐈 Server listening with saved key %q: %v\n", *flagKey, connStr)
	}
	if *flagJSON {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"listenAddr": string(connStr)})
	}
	if v := os.Getenv("TAILCAT_ADDR_FILE"); v != "" {
		if tcpAddr, ok := strings.CutPrefix(v, "tcp:"); ok {
			c, err := net.Dial("tcp", tcpAddr)
			if err != nil {
				log.Fatalf("TAILCAT_ADDR_FILE tcp dial %q: %v", tcpAddr, err)
			}
			fmt.Fprintln(c, connStr)
			c.Close()
		} else {
			if err := os.WriteFile(v, []byte(connStr), 0600); err != nil {
				log.Fatal(err)
			}
		}
	}

	if os.Getenv("TAILCAT_STATUS_LOOP") == "1" {
		go func() {
			for {
				log.Printf("status = %v", logger.AsJSON(s.Status()))
				time.Sleep(5 * time.Second)
			}
		}()
	}
	select {}
}

// parseFilesFlag parses the --files flag value: a directory with an
// optional :ro, :rw, :wo, or :wo+ suffix. An empty value means the current
// directory, read-only. It returns the file service and the mode's
// human-readable name.
func parseFilesFlag(v string) (*tailcat.FileService, string, error) {
	mode, modeName := tailcat.FileServeRO, "read-only"
	dir := v
	if d, ok := strings.CutSuffix(v, ":ro"); ok {
		dir = d
	} else if d, ok := strings.CutSuffix(v, ":rw"); ok {
		dir, mode, modeName = d, tailcat.FileServeRW, "read-write"
	} else if d, ok := strings.CutSuffix(v, ":wo+"); ok {
		dir, mode, modeName = d, tailcat.FileServeWOPlus, "recursive write-only"
	} else if d, ok := strings.CutSuffix(v, ":wo"); ok {
		dir, mode, modeName = d, tailcat.FileServeWO, "flat write-only"
	}
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, "", fmt.Errorf("--files: %w", err)
	}
	if !fi.IsDir() {
		return nil, "", fmt.Errorf("--files: %v is not a directory", abs)
	}
	return &tailcat.FileService{Dir: abs, Mode: mode}, modeName, nil
}

var (
	portRangeRx = regexp.MustCompile(`^\d+-\d+$`)
	numRx       = regexp.MustCompile(`^\d+$`)
)

func parsePortSet(s string) (ports set.Set[uint16], services set.Set[string], _ error) {
	services = set.Set[string]{}
	if s == "" {
		return nil, nil, nil
	}
	ret := set.Set[uint16]{}
	s = strings.TrimSpace(s)

	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		switch r {
		case "all":
			for i := 1; i <= 65535; i++ {
				ret.Add(uint16(i))
			}
			continue
		case "ssh", "no-auth-ssh", "files":
			if !tailCatSSHEnabled {
				return nil, nil, fmt.Errorf("SSH support not included in binary per build tags")
			}
			services.Add(r)
			continue
		case "exit-node":
			services.Add(r)
			continue
		}
		if !numRx.MatchString(r) && !portRangeRx.MatchString(r) {
			return nil, nil, fmt.Errorf("%q is not a known named service (want one of: all, ssh, no-auth-ssh, files, exit-node)", r)
		}
		a, b := r, ""
		if portRangeRx.MatchString(r) {
			a, b, _ = strings.Cut(r, "-")
		}

		lo, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("%q is not a valid port", a)
		}
		hi := lo
		if b != "" {
			hi, err = strconv.ParseUint(b, 10, 16)
			if err != nil {
				return nil, nil, fmt.Errorf("%q is not a valid port number", b)
			}
		}
		if hi < lo {
			hi, lo = lo, hi
		}
		for i := lo; i <= hi; i++ {
			ret.Add(uint16(i))
		}
	}
	return ret, services, nil
}

// portRanges coalesces the ascending-sorted ports into contiguous
// port ranges.
func portRanges(sorted []uint16) (ret []filter.PortRange) {
	for _, p := range sorted {
		if n := len(ret); n > 0 && ret[n-1].Last+1 == p {
			ret[n-1].Last = p
			continue
		}
		ret = append(ret, filter.PortRange{First: p, Last: p})
	}
	return ret
}

func runDevDERP(logf logger.Logf) (*derpserver.Server, *tailcfg.DERPRegion) {
	d := derpserver.New(key.NewNode(), logf)
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	logf("starting dev derp on %v ...", ln.Addr())

	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	httpsrv.Listener = ln
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	// Also serve STUN. Without it, netcheck burns ~3 seconds timing
	// out on UDP probes before it declares a report, which delays the
	// server's home DERP connection and thus its readiness.
	uln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	logf("starting dev STUN on %v ...", uln.LocalAddr())
	go func() {
		var buf [1500]byte
		for {
			n, src, err := uln.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return
			}
			txid, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			uln.WriteToUDPAddrPort(stun.Response(txid, src), src)
		}
	}()

	return d, &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "D",
		Nodes: []*tailcfg.DERPNode{
			{
				Name:             "t1",
				RegionID:         1,
				HostName:         "T",
				IPv4:             "127.0.0.1",
				IPv6:             "none", // netcheck's magic "no v6 probes" value; other values leave doomed probes running until its 3s timeout
				STUNPort:         uln.LocalAddr().(*net.UDPAddr).Port,
				DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
				InsecureForTests: true,
			},
		},
	}
}

func keyIsPath(name string) bool {
	return strings.ContainsAny(name, `/\`)
}

func keyPath(name string) string {
	if keyIsPath(name) {
		return name
	}
	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(confDir, "tailcat", "keys", name+".private.json")
}

func genKey(args []string) error {
	if *flagKey != "" {
		return usagef("genkey's --key argument must be after \"genkey\"")
	}
	if len(args) > 0 {
		return usagef("genkey takes no positional arguments")
	}

	confDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	var (
		key          = genkeyKey
		client       = genkeyClient
		force        = genkeyForce
		delete       = genkeyDelete
		list         = genkeyList
		region       = genkeyRegion
		fixedRegion  = genkeyFixedRegion
		embedDERPMap = genkeyEmbedDERPMap
		psk          = genkeyPSK
	)
	// isSet reports whether the named genkey flag was set explicitly,
	// as opposed to holding its default value.
	isSet := func(name string) bool {
		f, ok := genkeyFS.GetFlag(name)
		return ok && f.IsSet()
	}
	if *list {
		ents, err := os.ReadDir(filepath.Join(confDir, "tailcat", "keys"))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, e := range ents {
			if name, ok := strings.CutSuffix(e.Name(), ".private.json"); ok {
				fmt.Println(name)
			}
		}
		return nil
	}
	if *delete {
		if *key == "" {
			return usagef("genkey --delete requires saying which key to delete with --key=<name> (see genkey --list)")
		}
		if keyIsPath(*key) {
			return usagef("can't delete key %q; it's a path", *key)
		}
		return os.Remove(keyPath(*key))
	}
	if *key == "" && *region != "list" {
		if *client {
			return usagef("genkey requires a --key=<name>; client modes automatically load the key named \"client-default\" when it exists, making it the usual choice")
		}
		return usagef("genkey requires a --key=<name>; server mode automatically loads the key named \"default\" when it exists, making it the usual choice")
	}
	if *client {
		for _, name := range []string{"region", "fixed-region", "embed-derp-map"} {
			if isSet(name) {
				return usagef("genkey --client does not take --%s; client keys have no DERP region", name)
			}
		}
		if isSet("psk") {
			return usagef("genkey --client does not take --psk; pre-shared keys belong to server addresses")
		}
		if *key == "default" {
			return usagef("genkey --client with --key=default is probably a mistake: \"default\" is the name server mode loads automatically, and client modes load \"client-default\", so you likely want --key=client-default")
		}
	}
	if *fixedRegion {
		if isSet("region") {
			return usagef("genkey --fixed-region and --region are mutually exclusive")
		}
		// The empty region means "pick the best region now", below.
		*region = ""
	}
	if *embedDERPMap {
		// Embedding bakes one region's DERP nodes into the address,
		// so there has to be a specific region to bake in.
		switch {
		case isSet("region") && *region == "auto":
			return usagef("genkey --embed-derp-map and --region=auto are mutually exclusive; embedding needs a region chosen now, so use --fixed-region or name a region with --region")
		case strings.Contains(*region, "."):
			return usagef("genkey --embed-derp-map does not take DERP hostnames in --region; naming hosts already embeds them in the address")
		case !isSet("region"):
			// --region defaults to "auto", which has no nodes to
			// embed, so discover the nearest region now the way
			// --fixed-region does.
			*region = ""
		}
	}
	if !keyIsPath(*key) {
		*key = keyPath(*key)
		if err := os.MkdirAll(filepath.Dir(*key), 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(*key); err == nil {
		// The "list" mode exits before writing anything, so it
		// doesn't need --force.
		if !*force && *region != "list" {
			log.Fatalf("%v already exists; use --force to overwrite", *key)
		}
	}

	priv := tailcat.NewPrivateKey()
	if !*psk {
		priv.Public.PresharedKey = tailcat.PresharedKey{}
	}

	if *client {
		privj, err := json.MarshalIndent(priv, "", "\t")
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*key, privj, 0600); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "# wrote file to %v\n", *key)
		fmt.Println(priv.Private.Public().String())
		return nil
	}

	var match string
	if *region == "auto" {
		priv.Public.RegionID = -1
	} else if n, err := strconv.Atoi(*region); err == nil {
		priv.Public.RegionID = tailcfg.DERPRegionID(n)
	} else if strings.Contains(*region, ".") {
		hosts := strings.Split(*region, ",")
		reg := &tailcfg.DERPRegion{}
		priv.Public.Region = append(priv.Public.Region, reg)
		for _, host := range hosts {
			reg.Nodes = append(reg.Nodes, &tailcfg.DERPNode{
				HostName: host,
			})
		}
	} else {
		match = *region
	}

	var dm tailcfg.DERPMap
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if match != "" || *region == "" || *embedDERPMap {
		// genkey picks the region a future server will listen on,
		// hence ExpandForServer.
		got, err := tailcat.FetchDERPMap(ctx, tailcat.DERPMapURL(*flagDERPMapURL), tailcat.ExpandForServer, derpMapCache{})
		if err != nil {
			log.Fatalf("derpmap fetch: %v", err)
		}
		dm = *got
	}
	if *region == "" {
		id, err := tailcat.PickBestRegion(ctx, &dm)
		if err != nil {
			log.Fatal(err)
		}
		if id == 0 {
			log.Fatalf("couldn't determine the closest DERP region; specify --region")
		}
		priv.Public.RegionID = id
	}

	ci := &priv.Public
	if match != "" {
		ci.RegionID = findRegionIDFromSubstring(&dm, match)
		if ci.RegionID == 0 {
			regs := xmaps.Values(dm.Regions)
			slices.SortFunc(regs, func(a, b *tailcfg.DERPRegion) int { return cmp.Compare(a.RegionID, b.RegionID) })
			for _, reg := range regs {
				fmt.Fprintf(os.Stderr, "  %3d %s %s\n", reg.RegionID, reg.RegionCode, reg.RegionName)
			}
			if match == "list" {
				os.Exit(0)
			}
			log.Fatalf("\nno region found matching %q", match)
		}
	}
	if *embedDERPMap {
		reg := dm.Regions[ci.RegionID]
		if reg == nil {
			log.Fatalf("no DERP region %d in the DERP map; can't embed its nodes", ci.RegionID)
		}
		reg.Nodes = reg.Nodes[:min(2, len(reg.Nodes))]
		for _, n := range reg.Nodes {
			n.IPv6 = ""
		}
		ci.Region = append(ci.Region, reg)
		ci.RegionID = 0
	}

	privj, err := json.MarshalIndent(priv, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*key, privj, 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "# wrote file to %v\n", *key)
	fmt.Println(priv.Public.Addr())
	return nil
}

// or returns 0 on no match
func findRegionIDFromSubstring(dm *tailcfg.DERPMap, s string) (regionID tailcfg.DERPRegionID) {
	if s == "list" {
		return 0
	}
	// First look my region code
	for _, r := range dm.Regions {
		if strings.EqualFold(r.RegionCode, s) {
			return r.RegionID
		}
	}
	// Then look by substring
	for _, r := range dm.Regions {
		if mem.ContainsFold(mem.S(r.RegionName), mem.S(s)) {
			return r.RegionID
		}
	}
	return 0
}

func clearUnnecessaryRegionFields(r *tailcfg.DERPRegion) {
	r.Latitude = 0
	r.Longitude = 0
	r.RegionCode = ""
	if len(r.Nodes) > 1 {
		r.Nodes = r.Nodes[:1]
	}
	for _, n := range r.Nodes {
		n.CanPort80 = false
		n.RegionID = 0
	}
}
