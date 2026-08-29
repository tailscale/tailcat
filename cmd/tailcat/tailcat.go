// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"go4.org/mem"
	xmaps "golang.org/x/exp/maps"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/socks5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
)

var (
	flagServe       = flag.String("serve", "", "comma-separated list of port numbers, port ranges, or service names to serve. Service names are: 'all' (serve all ports), 'exit-node' (run an exit node for all addresses), 'no-auth-ssh' (auth-free SSH server). If empty, it listens only on port 0 and writes to stdout.")
	flagKey         = flag.String("key", "", "'new' for an ephemeral key. If empty, the default saved key is used if it exists ('default' in server mode, 'client-default' in client modes; see genkey), else an ephemeral key. Otherwise the path to a *.private.json or a name like 'foo' to read it from $CONFIG/tailcat/keys/foo.private.json")
	flagAllow       = flag.String("allow", "", "comma-separated list of public keys to allow access to the server, or 'none' to allow no clients. If empty, all clients are allowed.")
	flagVerbose     = flag.Bool("verbose", false, "be verbose")
	flagReadme      = flag.Bool("readme", false, "print the tailcat README (documentation with usage examples) and exit")
	flagFullAddress = flag.Bool("full-address", false, "in server mode, print a longer connection address token with embedded DERP server info instead of a reference to a DERP map region ID. This lets clients connect more quickly, without a DERP map fetch.")
	flagJSON        = flag.Bool("json", false, "in server mode, write {\"listenAddr\": ...} JSON to stdout")

	flagDERPMapURL = flag.String("derpmap-url", tailcat.DefaultDERPMapURL, "URL of the JSON DERP map used to resolve or auto-select a DERP region")
)

func usage(err string) {
	if err != "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	}
	fmt.Fprintf(os.Stderr, `Usage:

Server mode, accept one connection (any port), write to stdout:

	tailcat

Server mode, given ports:

	tailcat --serve=22,80,443,8000-8999

Server mode, all ports:

	tailcat --serve=all

Server mode, certain ports and Tailscale SSH (auth without
password or public key):

	tailcat --serve=80,no-auth-ssh

Server mode, exit node (clients can reach the server's whole network):

	tailcat --serve=exit-node

Client mode, to default port 0 for stdin/stdout pipe:

	echo hello | tailcat <addrblob>

Client mode to an explicit port:

	echo "GET / HTTP/1.1..." | tailcat <addrblob> 80

Anywhere an <addrblob> argument is accepted, a DNS name whose
"tailcat=" TXT record contains one may be used instead:

	tailcat ssh example.com

Client mode, ping. Each pong reports whether it arrived via a DERP
relay or a direct path. --until-direct keeps pinging (bounded by
--timeout, default 10s) until a direct path works:

	tailcat ping <addrblob>
	tailcat ping --until-direct <addrblob>

Client mode, ssh:

	tailcat ssh [user@]<addrblob>
	tailcat ssh [user@]<addrblob> <command> [args...]

Client mode, ssh to specific IP:port via addrblob's exit node:

	tailcat ssh -p 10.0.0.1:22 <addrblob>

Client mode, run an ephemeral SOCKS5 proxy and pass its address
as 'all_proxy' environment variable to a child process. Destination
hostnames that are themselves address blobs are dialed as tailcat
servers, so the <addrblob> argument is optional:

	tailcat socks [-listen <addr:port>] [<addrblob>] [<cmd> [args...]]
	tailcat socks <addrblob> curl http://server.tailcat:8081/
	tailcat socks curl http://<addrblob>:8081/

If you don't specify the cmd, just the proxy server will start.

Parse an address blob and print its encoded fields as JSON:

	tailcat parse <addrblob>

Resolve a short address blob into a longer self-contained one with
embedded DERP server info (see also the server's --full-address flag):

	tailcat resolve <addrblob>

Print the public key of the client key that would be used (see --key):

	tailcat printpub

Generate and save a persistent server key and print its address blob
(run "tailcat genkey --help" for its flags):

	tailcat genkey [--key=<name>] [--force]

Generate and save a persistent client key and print its public key,
for use in a server's --allow list. Client modes automatically use
the key named "client-default" when it exists:

	tailcat genkey --client

List or delete saved keys:

	tailcat genkey --list
	tailcat genkey --delete --key=<name>

Print the full documentation (the project README) with more examples:

	tailcat --readme

Environment:

	TAILCAT_ADDR_FILE: in server mode, write the address blob to the
	given file path or, with a "tcp:" prefix, send it to that TCP
	address.

Flags:

`)
	// Print the flag defaults with double hyphens (Go's single-hyphen
	// style weirds people out, and the flag package accepts both).
	var b strings.Builder
	flag.CommandLine.SetOutput(&b)
	flag.PrintDefaults()
	os.Stderr.WriteString(strings.ReplaceAll("\n"+b.String(), "\n  -", "\n  --")[1:])
	os.Exit(1)
}

func main() {
	flag.Usage = func() { usage("") }
	flag.Parse()
	if *flagReadme {
		os.Stdout.WriteString(tailcat.README)
		return
	}
	if *flagVerbose {
		tailcat.Verbose = true
	}
	args := flag.Args()
	serverMode := len(args) == 0 || *flagServe != ""
	if len(args) > 0 && serverMode {
		usage("No positional arguments are valid along with --serve")
	}
	var logf logger.Logf = logger.Discard
	if *flagVerbose {
		logf = log.Printf
	}
	if serverMode {
		server(logf)
		return
	}
	switch args[0] {
	case "help":
		usage("")
	case "ping":
		clientPingMode(logf)
	case "socks":
		clientSOCKSMode(logf)
	case "ssh":
		clientSSHMode(logf)
	case "parse":
		clientParseMode(logf)
	case "resolve":
		clientResolveMode()
	case "genkey":
		genKey()
	case "printpub":
		fmt.Println(clientKey().Public().String())
	default:
		var dst string
		if len(args) == 2 {
			dst = args[1]
		}
		clientMode(logf, string(addrBlobArg(args[0])), dst)
	}
}

// addrBlobArg interprets a CLI destination argument as either a
// "tc"-prefixed address blob or a DNS name whose "tailcat=" TXT
// record holds one. A dot can never appear in a base64 address blob,
// so anything containing one is treated as a DNS name; that also
// keeps DNS names starting with "tc" working. It exits the process
// on failure.
func addrBlobArg(arg string) tailcat.ConnBlob {
	if strings.Contains(arg, ".") {
		var r net.Resolver
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		txts, err := r.LookupTXT(ctx, arg)
		if err != nil {
			log.Fatalf("looking up TXT record for %q: %v", arg, err)
		}
		for _, txt := range txts {
			if suf, ok := strings.CutPrefix(txt, "tailcat="); ok {
				return tailcat.ConnBlob(strings.TrimSpace(suf))
			}
		}
		log.Fatalf("no \"tailcat=\" TXT record found for %q", arg)
	}
	if !strings.HasPrefix(arg, "tc") {
		log.Fatalf("argument %q is neither a \"tc\"-prefixed address blob nor a DNS name", arg)
	}
	return tailcat.ConnBlob(arg)
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
func newClient(logf logger.Logf, blob tailcat.ConnBlob, priv key.NodePrivate) *tailcat.Client {
	return &tailcat.Client{
		Server:       blob,
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

func clientPingMode(logf logger.Logf) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	untilDirect := fs.Bool("until-direct", false, "keep pinging until a pong arrives over a direct (non-DERP) path; exit non-zero if that doesn't happen before --timeout")
	timeout := fs.Duration("timeout", 10*time.Second, "give up after this long")
	fs.Parse(flag.Args()[1:]) // stripping off "ping"
	if len(fs.Args()) != 1 {
		usage("tailcat ping [--until-direct] [--timeout=10s] <addrblob>")
	}
	cl := newClient(logf, addrBlobArg(fs.Args()[0]), clientKey())
	defer cl.Close()

	deadline := time.Now().Add(*timeout)
	for {
		t0 := time.Now()
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		res, err := cl.DiscoPing(ctx)
		cancel()
		if err != nil {
			if *untilDirect && errors.Is(err, context.DeadlineExceeded) {
				log.Fatalf("no direct path to the server after %v", *timeout)
			}
			log.Fatalf("ping: %v", err)
		}
		latency := time.Duration(res.LatencySeconds * float64(time.Second)).Round(10 * time.Microsecond)
		direct := res.Endpoint != ""
		via := res.Endpoint
		if !direct {
			via = fmt.Sprintf("DERP(%v)", cmp.Or(res.DERPRegionCode, strconv.Itoa(res.DERPRegionID)))
		}
		fmt.Printf("pong in %v via %v\n", latency, via)
		if direct || !*untilDirect {
			return
		}
		if time.Until(deadline) < time.Second/2 {
			log.Fatalf("no direct path to the server after %v", *timeout)
		}
		time.Sleep(max(0, time.Second-time.Since(t0)))
	}
}

func clientMode(logf logger.Logf, connStr, optDest string) {
	cl := newClient(logf, tailcat.ConnBlob(connStr), clientKey())

	var dial func(context.Context) (net.Conn, error)
	switch {
	case optDest == "":
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, 1) }
	case !strings.Contains(optDest, ":"):
		port, err := strconv.ParseUint(optDest, 10, 16)
		if err != nil {
			usage(fmt.Sprintf("invalid port number %q", optDest))
		}
		dial = func(ctx context.Context) (net.Conn, error) { return cl.DialTCPPort(ctx, uint16(port)) }
	default:
		addrPort, err := netip.ParseAddrPort(optDest)
		if err != nil {
			usage(fmt.Sprintf("invalid IP:port %q", optDest))
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
}

// This function will only fill in the missing part.
// 0.0.0.0 and 0 will be used for the address and port respectively.
// It won't validate the input, we delegate this to the following socket creation
func normalizeListenAddrPort(s string) string {
	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			host = "0.0.0.0"
		}
		if port == "" {
			port = "0"
		}
		return net.JoinHostPort(host, port)
	} else if port, err := strconv.ParseUint(s, 10, 16); err == nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	}
	// Assume it's hostname
	return s + ":0"
}

func clientSOCKSMode(logf logger.Logf) {
	fs := flag.NewFlagSet("socks", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "Proxy server's listen address")
	fs.Parse(flag.Args()[1:]) // stripping off "socks"
	args := fs.Args()

	lisenAddrPort := normalizeListenAddrPort(*listen)

	// The address blob argument is optional: destination hostnames that
	// are themselves address blobs are dialed directly (see
	// classifySOCKSAddr), so a fixed server is only needed for the
	// server.tailcat magic name and exit-node destinations.
	var blob tailcat.ConnBlob
	if len(args) > 0 {
		if _, err := tailcat.ParseConnBlob(tailcat.ConnBlob(args[0])); err == nil {
			blob = tailcat.ConnBlob(args[0])
			args = args[1:]
		} else if strings.Contains(args[0], ".") {
			if _, err := exec.LookPath(args[0]); err != nil {
				// Not a runnable command, so treat it as a DNS name
				// holding an address blob in a TXT record.
				blob = addrBlobArg(args[0])
				args = args[1:]
			}
		}
	}
	progArgs := args

	var cl *tailcat.Client
	if blob != "" {
		cl = newClient(logf, blob, key.NewNode())
		pi, err := cl.Ping(context.Background())
		if err != nil {
			log.Fatalf("tailcat Ping: %v", err)
		}
		logf("got ping: %+v", pi)
	}

	var clientsMu sync.Mutex
	clients := map[tailcat.ConnBlob]*tailcat.Client{}
	if cl != nil {
		clients[blob] = cl
	}
	clientForBlob := func(b tailcat.ConnBlob) *tailcat.Client {
		clientsMu.Lock()
		defer clientsMu.Unlock()
		if c, ok := clients[b]; ok {
			return c
		}
		c := newClient(logf, b, key.NewNode())
		clients[b] = c
		return c
	}

	socksLn, err := net.Listen("tcp", lisenAddrPort)
	if err != nil {
		log.Fatal(err)
	}
	ss := &socks5.Server{
		Logf: logger.WithPrefix(logf, "socks5: "),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dst, err := classifySOCKSAddr(ctx, lookupNetIP, addr)
			if err != nil {
				return nil, err
			}
			if dst.blob != "" {
				return clientForBlob(dst.blob).DialTCPPort(ctx, dst.port)
			}
			if cl == nil {
				return nil, errors.New("no address blob argument was given to \"tailcat socks\"; only address blob hostnames can be dialed")
			}
			if dst.toServer {
				return cl.DialTCPPort(ctx, dst.port)
			}
			return cl.DialTCP(ctx, dst.dst)
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
		fmt.Printf("SOCKS running at %v\n", socksAddr)
		log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksLn))
	}
}

// socksTarget is where a SOCKS5 destination address should be dialed.
type socksTarget struct {
	toServer bool             // dial the tailcat server from the command line
	blob     tailcat.ConnBlob // if non-empty, the address blob hostname to dial
	port     uint16           // the port to dial, if toServer or blob is set
	dst      netip.AddrPort   // the IP:port to dial through the server as an exit node, otherwise
}

// lookupNetIP resolves host using the local resolver, for
// [classifySOCKSAddr].
func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// classifySOCKSAddr decides where the SOCKS5 destination addr should be
// dialed. The magic hostname "server.tailcat" (or an empty host) means the
// tailcat server itself. A hostname that is a valid address blob (which can
// never contain a dot) means the server that blob names, letting blobs be
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
		if _, err := tailcat.ParseConnBlob(tailcat.ConnBlob(host)); err == nil {
			return socksTarget{blob: tailcat.ConnBlob(host), port: uint16(portNum)}, nil
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

func clientParseMode(logf logger.Logf) {
	args := flag.Args()
	if len(args) != 2 {
		usage("tailcat parse <addrblob>")
	}
	v, err := tailcat.ParseConnBlobRaw(tailcat.ConnBlob(args[1]))
	if err != nil {
		log.Fatal(err)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "    ")
	e.Encode(v)
}

func clientResolveMode() {
	args := flag.Args()
	if len(args) != 2 {
		usage("tailcat resolve <addrblob>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rb, err := addrBlobArg(args[1]).Resolve(ctx, tailcat.DERPMapURL(*flagDERPMapURL), derpMapCache{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rb)
}

func server(logf logger.Logf) {
	portSet, services, err := parsePortSet(*flagServe)
	if err != nil {
		log.Fatalf("invalid value in --serve: %v", err)
	}

	var reg *tailcfg.DERPRegion
	if envknob.Bool("TS_DEBUG_TAILCAT_LOCAL_DERP") {
		log.Printf("Local DERP mode.")
		reg = runDevDERP(logger.WithPrefix(logf, "[dev-derp] "))
	}

	var priv key.NodePrivate
	var ci *tailcat.ConnInfo

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
		priv = key.NewNode()
		ci = &tailcat.ConnInfo{RegionID: -1} // auto-detect
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
	}
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

		ci = &tailcat.ConnInfo{ServerPublic: tailcat.NodePublic{NodePublic: priv.Public()}}
		if embed {
			ci.Region = []*tailcfg.DERPRegion{reg}
		} else {
			ci.RegionID = reg.RegionID
		}
	}
	connStr := ci.ConnBlob()

	s := &tailcat.Server{Key: priv, Logf: logf, Region: reg}
	if services.Contains("no-auth-ssh") && !tailcat.SupportsSSHServer() {
		log.Fatalf("Tailscale SSH server not supported on %v", runtime.GOOS)
	}
	// With an explicit port list (and no exit-node mode, which accepts
	// any port), tighten the packet filter to just those ports for
	// defense in depth behind the OnTCP gate. An empty port list means
	// the accept-one-connection-on-any-port stdout mode.
	if len(portSet) > 0 && !services.Contains("exit-node") {
		ports := slices.Sorted(maps.Keys(portSet))
		if services.Contains("no-auth-ssh") && !portSet.Contains(22) {
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

	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		if port == 22 && services.Contains("no-auth-ssh") && tailCatSSHEnabled {
			return s.HandleTailscaleSSHConn
		}
		if services.Contains("exit-node") {
			// Being an exit node includes localhost without needing
			// to specify all the local port ranges.
			return tcpForwardTo(fmt.Sprintf("localhost:%v", port))
		}
		if len(portSet) == 0 {
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
		case "no-auth-ssh":
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
			return nil, nil, fmt.Errorf("%q is not a known named service (want one of: all, no-auth-ssh, exit-node)", r)
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

func runDevDERP(logf logger.Logf) *tailcfg.DERPRegion {
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

	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "D",
		Nodes: []*tailcfg.DERPNode{
			{
				Name:             "t1",
				RegionID:         1,
				HostName:         "T",
				IPv4:             "127.0.0.1",
				IPv6:             "-",
				STUNPort:         -1, // no STUN server in dev DERP mode
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

func genKey() {
	if *flagKey != "" {
		log.Fatalf("genkey's --key argument must be after \"genkey\"")
	}
	args := flag.Args()
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)

	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	var (
		key          = fs.String("key", "", "key path (if it contains a slash) or name (written to "+confDir+"/tailcat/keys/<name>.private.json). If empty, 'default' is used, or 'client-default' with --client.")
		client       = fs.Bool("client", false, "generate a client identity key (no DERP region) and print its public key, for use with servers' --allow lists. The 'client-default' key is used automatically by client modes.")
		force        = fs.Bool("force", false, "force overwrite of existing key")
		delete       = fs.Bool("delete", false, "delete the key named by --key instead of generating one; --key is required and must be a name, not a path")
		list         = fs.Bool("list", false, "list saved key names and exit")
		region       = fs.String("region", "auto", "region ID, code, or substring to use. Or a hostname(s) comma-separated to use a custom DERP server(s). If 'auto', one is picked based on latency at each server startup. If 'list', list all regions.")
		fixedRegion  = fs.Bool("fixed-region", false, "discover the nearest DERP region once, now, and bake it into the key and token, so future server startups (and clients) use it without re-probing")
		embedDERPMap = fs.Bool("embed-derp-map", false, "embed the DERP map nodes in the connection string")
	)
	fs.Parse(args[1:]) // stripping off "genkey"
	switch len(fs.Args()) {
	case 0:
	default:
		fmt.Fprintf(os.Stderr, "tailcat genkey [--client] [--key=<name>] [--force]\n")
		os.Exit(1)
	}
	if *list {
		ents, err := os.ReadDir(filepath.Join(confDir, "tailcat", "keys"))
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
		for _, e := range ents {
			if name, ok := strings.CutSuffix(e.Name(), ".private.json"); ok {
				fmt.Println(name)
			}
		}
		return
	}
	if *delete {
		if *key == "" {
			log.Fatalf("genkey --delete requires saying which key to delete with --key=<name> (see genkey --list)")
		}
		if keyIsPath(*key) {
			log.Fatalf("can't delete key %q; it's a path", *key)
		}
		if err := os.Remove(keyPath(*key)); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *key == "" {
		if *client {
			*key = "client-default"
		} else {
			*key = "default"
		}
	}
	if *client {
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "region", "fixed-region", "embed-derp-map":
				log.Fatalf("genkey --client does not take --%s; client keys have no DERP region", f.Name)
			}
		})
	}
	if *fixedRegion {
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "region" {
				log.Fatalf("genkey --fixed-region and --region are mutually exclusive")
			}
		})
		// The empty region means "pick the best region now", below.
		*region = ""
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
		return
	}

	var match string
	if *region == "auto" {
		priv.Public.RegionID = -1
	} else if n, err := strconv.Atoi(*region); err == nil {
		priv.Public.RegionID = n
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
	fmt.Println(priv.Public.ConnBlob())
}

// or returns 0 on no match
func findRegionIDFromSubstring(dm *tailcfg.DERPMap, s string) (regionID int) {
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
