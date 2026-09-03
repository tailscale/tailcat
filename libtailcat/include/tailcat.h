// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// libtailcat: a C API over the tailcat Go library.
//
// tailcat is a control-plane-free network pipe built on Tailscale's data
// plane (WireGuard encryption, NAT traversal, DERP relays as bootstrap and
// fallback). A server announces a tailcat address; clients holding the
// address can dial TCP ports on the server, which hands each accepted
// connection to the caller as a file descriptor.
//
// Every connection given to C is one end of a socketpair(2) pumped by the
// Go side: use read(2), write(2), shutdown(2) and close(2) on it like a
// socket. shutdown(fd, SHUT_WR) is a TCP half-close: the peer's reads see
// EOF while its writes still reach you. close(2) tears the connection down.
// On Apple platforms every descriptor handed out has SO_NOSIGPIPE set, so
// writing to a dead connection fails with EPIPE instead of raising SIGPIPE.
// Every descriptor handed out is close-on-exec, so a child process the
// caller spawns does not inherit it and keep the connection alive.
//
// Every function is safe to call from any thread. Functions documented as
// blocking (server start, client ping, path, dial, address resolve) do
// network work and must not be called on a UI thread.

#include <stddef.h>

#ifndef TAILCAT_H
#define TAILCAT_H

#ifdef __cplusplus
extern "C" {
#endif

// tailcat_handle refers to a server or a client object.
typedef int tailcat_handle;

// tailcat_conn is one end of a socketpair: read(2), write(2), shutdown(2),
// close(2). See the file comment above.
typedef int tailcat_conn;

// tailcat_listener is one end of a socketpair over which accepted
// connections arrive. poll(2) it for POLLIN, then call tailcat_accept.
// close(2) it to stop listening, which also unregisters its port.
typedef int tailcat_listener;

// Handle functions return 0 on success, EBADF for an invalid handle (or a
// handle of the wrong kind, such as a client passed to a server function),
// ERANGE when an output buffer is too small (the output is still
// NUL-terminated), or -1 for any other error, whose text tailcat_errmsg
// returns. Functions taking an output buffer panic on a NULL buffer or a
// zero length, and functions taking an output pointer (listener_out,
// conn_out, json_out, ...) panic when it is NULL; that is a programming
// error, not a runtime condition.

// tailcat_errmsg writes the text of the last error recorded on h to buf.
//
// After returning, buf is always NUL-terminated.
//
// Returns:
// 	0      - success
// 	EBADF  - h is not a valid handle
// 	ERANGE - insufficient storage for buf
extern int tailcat_errmsg(tailcat_handle h, char* buf, size_t buflen);

// tailcat_set_logfd sends the object's Go-side logs to fd, one line per
// message. An fd of -1 discards them. By default they go to Go's log
// package, that is, to stderr.
//
// The descriptor stays owned by the caller and must remain open for the
// life of the handle; libtailcat never closes it. Call this before
// tailcat_server_start, or before a client's first ping, path or dial;
// afterwards it fails with -1.
extern int tailcat_set_logfd(tailcat_handle h, int fd);

// Server.

// tailcat_server_new creates a server object. Nothing touches the network
// until tailcat_server_start.
extern tailcat_handle tailcat_server_new(void);

// tailcat_server_set_key sets the server's identity from key_json, the JSON
// of a tailcat.PrivateKey as written by "tailcat genkey" (or returned by
// tailcat_key_generate). It adopts both the private key and the DERP
// region information recorded in the key's Public part: a fixed region
// ID, embedded relay hosts, or -1 for automatic selection. A key with no
// region information at all (a client key) means automatic selection.
//
// Without a key, the server generates an ephemeral one. Call before start.
extern int tailcat_server_set_key(tailcat_handle sd, const char* key_json);

// tailcat_server_set_region_id selects the DERP map region the server
// listens on: a positive region ID from the DERP map, or 0 to pick the
// nearest region by latency at start. It overrides the region information
// from the key and any earlier tailcat_server_set_relay_hosts call: of the
// key, set_region_id and set_relay_hosts, the last one applied wins.
//
// Call before start.
extern int tailcat_server_set_region_id(tailcat_handle sd, int region_id);

// tailcat_server_set_relay_hosts uses your own DERP relay instead of one
// from the DERP map: hosts is a comma-separated list of DERP server
// hostnames. Like the tailcat CLI, the server connects to the first host
// listed. Because such a relay has no DERP map region ID to reference, the
// address always embeds the relay details. It overrides the region from the
// key and any earlier tailcat_server_set_region_id call.
//
// Call before start.
extern int tailcat_server_set_relay_hosts(tailcat_handle sd, const char* hosts);

// tailcat_server_set_derpmap_url sets the URL of the JSON DERP map used to
// resolve or auto-select the region. The default is
// tailcat.DefaultDERPMapURL (https://tailcat.dev/derpmap.json).
//
// Call before start.
extern int tailcat_server_set_derpmap_url(tailcat_handle sd, const char* url);

// tailcat_server_set_embed_relay controls the address form. With embed set
// to 1, the address embeds the relay's details (hostname and IP addresses)
// so that clients need no DERP map fetch; it is longer, like the output of
// "tailcat serve --full-address". With 0 (the default) the address carries
// just the DERP map region ID. Relay hosts set with
// tailcat_server_set_relay_hosts are always embedded.
//
// Call before start.
extern int tailcat_server_set_embed_relay(tailcat_handle sd, int embed);

// tailcat_server_allow_client restricts the server to known clients:
// nodekey is a client's public key in the "nodekey:<hex>" form that
// tailcat_client_public_key returns. It may be called before or after
// start.
//
// The allow-list gates registration. Until any key is allowed, every
// client may register (its first ping is answered); once one is, only
// allowed clients can. A client that registered while the list was empty
// stays registered: its tunnel keeps working, its later pings still
// succeed and it can still open connections, until the server closes or
// the client restarts. To lock a server down from the start, allow its
// clients before tailcat_server_start.
extern int tailcat_server_allow_client(tailcat_handle sd, const char* nodekey);

// tailcat_server_listen registers port (1-65535) for incoming connections
// and writes the new listener to listener_out. Port 0 registers a
// catch-all listener that receives connections to every port that has no
// listener of its own. Connections to ports with no listener (and no
// catch-all) are refused with a TCP RST.
//
// A port may be registered once until its listener is closed. Listening
// works before and after start.
//
// Returns zero on success or -1 on error, call tailcat_errmsg for details.
extern int tailcat_server_listen(tailcat_handle sd, int port, tailcat_listener* listener_out);

// tailcat_server_start resolves the DERP region (fetching the DERP map and
// running a latency check as needed) and starts the server. It blocks for
// the duration, typically a few seconds; never call it on a UI thread. A
// server starts once.
//
// Like the tailcat CLI, it returns once the server is configured; the
// connection to the relay itself completes in the background shortly
// after. A client pinging in that window gets no answer (see
// tailcat_client_ping) and should retry.
//
// Returns zero on success or -1 on error, call tailcat_errmsg for details.
extern int tailcat_server_start(tailcat_handle sd);

// tailcat_server_addr writes the server's tailcat address, the string
// clients pass to tailcat_client_new (or to the tailcat CLI), to buf.
// Valid after start.
//
// Returns 0, EBADF, ERANGE or -1 as described at the top of this file.
extern int tailcat_server_addr(tailcat_handle sd, char* buf, size_t buflen);

// tailcat_server_public_key writes the server's node public key
// ("nodekey:<hex>") to buf. Valid any time after tailcat_server_new.
extern int tailcat_server_public_key(tailcat_handle sd, char* buf, size_t buflen);

// tailcat_server_status_json writes the server's WireGuard and DERP status
// (the JSON encoding of ipnstate.Status) to *json_out as a malloc'd,
// NUL-terminated string that the caller releases with free(). Valid after
// start.
//
// Returns:
// 	0     - success, *json_out is set
// 	EBADF - sd is not a valid server handle
// 	-1    - call tailcat_errmsg for details (*json_out is NULL)
extern int tailcat_server_status_json(tailcat_handle sd, char** json_out);

// tailcat_server_close shuts the server down: every listener and every
// accepted connection is closed on the Go side (reads on their
// descriptors return EOF; the caller still close(2)s the descriptors it
// holds), the relay connection is torn down and the handle is freed. It
// may be called before start. A second call returns EBADF.
//
// Returns:
// 	0     - success
// 	EBADF - sd is not a valid server handle
// 	-1    - other error, details go to the logger
extern int tailcat_server_close(tailcat_handle sd);

// tailcat_accept dequeues the next accepted connection from listener l
// into conn_out. It blocks until a connection is queued; poll(2) the
// listener for POLLIN first to avoid blocking. Once the listener is closed
// it fails with -1.
//
// Returns:
// 	0     - success
// 	EBADF - l is not a valid listener
// 	-1    - call tailcat_errmsg (on the server handle) for details
extern int tailcat_accept(tailcat_listener l, tailcat_conn* conn_out);

// tailcat_conn_info describes a connection c accepted from listener l: the
// peer's address as "ip:port" (an IPv6 address in brackets) is written to
// remote_buf and the server port the peer dialed to *local_port_out, which
// may be NULL. It only knows connections returned by tailcat_accept on l,
// not connections from tailcat_client_dial.
//
// Returns:
// 	0      - success
// 	EBADF  - l is not a valid listener, or c was not accepted from it
// 	ERANGE - insufficient storage for remote_buf
extern int tailcat_conn_info(tailcat_listener l, tailcat_conn c, char* remote_buf, size_t remote_buflen, int* local_port_out);

// Client.

// tailcat_client_new creates a client for the server named by addr, its
// tailcat address. It returns 0 if the address is malformed (there is no
// handle to record an error on), otherwise a handle. Nothing happens on
// the network until the first ping, path or dial, which brings the client
// up: it resolves the server's relay (fetching the DERP map if the address
// doesn't embed it), connects to it and registers with the server.
extern tailcat_handle tailcat_client_new(const char* addr);

// tailcat_client_set_key sets the client's identity from key_json, the JSON
// of a tailcat.PrivateKey (only its Private part is used), so a server can
// allow it by public key. Without one, an ephemeral key is generated.
// Call before the client's first use, and before
// tailcat_client_public_key; afterwards it fails with -1.
extern int tailcat_client_set_key(tailcat_handle cd, const char* key_json);

// tailcat_client_set_derpmap_url sets the DERP map URL used when the
// address doesn't embed the relay details. Call before the client's first
// use.
extern int tailcat_client_set_derpmap_url(tailcat_handle cd, const char* url);

// tailcat_client_public_key writes the client's node public key
// ("nodekey:<hex>") to buf: the key set with tailcat_client_set_key, or
// else the ephemeral key generated by tailcat_client_new. Give this to
// the server's tailcat_server_allow_client. It never blocks, not even
// while a ping or dial is bringing the client up on another thread.
extern int tailcat_client_public_key(tailcat_handle cd, char* buf, size_t buflen);

// tailcat_client_ping checks that the server is reachable and accepts this
// client, bringing the client up on first use. It measures the relay round
// trip and writes it in milliseconds to *latency_ms_out (which may be
// NULL). It blocks for up to timeout_ms milliseconds; a timeout of 0 or
// less means no limit beyond tailcat's own internal one.
//
// Each call sends one probe. A server that doesn't allow this client never
// answers, so a rejected client shows up as a timeout; so does a server
// that is still connecting to its relay right after tailcat_server_start,
// which is worth a retry.
//
// Returns zero on success or -1 on error, call tailcat_errmsg for details.
extern int tailcat_client_ping(tailcat_handle cd, int timeout_ms, double* latency_ms_out);

// tailcat_client_path_json reports how packets reach the server: it sends
// a path-discovery ping (Client.DiscoPing) and writes the result, the JSON
// encoding of ipnstate.PingResult, to *json_out as a malloc'd string that
// the caller releases with free(). Endpoint is set when the pong came back
// over a direct path; otherwise DERPRegionID and DERPRegionCode name the
// relay. LatencySeconds is the round trip. Calling it repeatedly nudges
// direct path discovery along. It blocks for up to timeout_ms
// milliseconds (0 or less: no limit) and brings the client up on first
// use.
//
// Returns zero on success or -1 on error (*json_out is NULL), call
// tailcat_errmsg for details.
extern int tailcat_client_path_json(tailcat_handle cd, int timeout_ms, char** json_out);

// tailcat_client_dial opens a TCP connection to port (1-65535) on the
// server's own address and writes it to conn_out. It blocks for up to
// timeout_ms milliseconds (0 or less: no limit) and brings the client up
// on first use.
//
// Returns zero on success or -1 on error, call tailcat_errmsg for details.
extern int tailcat_client_dial(tailcat_handle cd, int port, int timeout_ms, tailcat_conn* conn_out);

// tailcat_client_close closes every connection dialed through the client
// on the Go side (reads on their descriptors return EOF; the caller still
// close(2)s them), shuts the tunnel down and frees the handle. A second
// call returns EBADF. If a first ping, path or dial is bringing the
// client up on another thread, close waits for that bring-up (the DERP
// map fetch and relay setup) to finish first.
//
// Returns:
// 	0     - success
// 	EBADF - cd is not a valid client handle
// 	-1    - other error, details go to the logger
extern int tailcat_client_close(tailcat_handle cd);

// Keys and addresses. These take no handle. They return NULL on success or a
// malloc'd error string. All outputs are malloc'd and NUL-terminated; the
// caller releases outputs and error strings with free().

// tailcat_key_generate creates a new identity and writes its JSON (the
// format of "tailcat genkey" key files, a tailcat.PrivateKey with
// Public.RegionID = -1 for automatic region selection) to *key_json_out.
// It is a private key: store it accordingly.
extern char* tailcat_key_generate(char** key_json_out);

// tailcat_key_public writes the public key ("nodekey:<hex>") of the
// identity in key_json to *nodekey_out.
extern char* tailcat_key_public(const char* key_json, char** nodekey_out);

// tailcat_key_addr writes the tailcat address that a server using key_json
// will announce to *addr_out. That is only known ahead of time when the
// key names a fixed DERP region or embeds relay hosts; with automatic
// region selection (RegionID -1) it fails, and the address must instead be
// read from the running server with tailcat_server_addr.
extern char* tailcat_key_addr(const char* key_json, char** addr_out);

// tailcat_addr_parse decodes the tailcat address addr and writes its
// fields as JSON to *json_out: ServerPublic, ServerDiscoPublic, and either
// RegionID or the embedded Region. It is the same output as "tailcat
// parse".
extern char* tailcat_addr_parse(const char* addr, char** json_out);

// tailcat_addr_resolve writes a self-contained form of the tailcat address
// addr, with the relay's details embedded, to *addr_out, the same as
// "tailcat resolve". An address that already embeds them is returned
// unchanged. The DERP map is fetched from derpmap_url, or the default map
// when derpmap_url is NULL or empty. It blocks for up to timeout_ms
// milliseconds (0 or less: no limit beyond the fetch's own).
extern char* tailcat_addr_resolve(const char* addr, const char* derpmap_url, int timeout_ms, char** addr_out);

#ifdef __cplusplus
}
#endif

#endif
