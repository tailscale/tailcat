// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Tailcat C library.
//
// Use this library to compile tailcat into your program: a
// control-plane-free encrypted pipe (WireGuard + NAT traversal,
// bootstrapped over a DERP relay) between a server and its clients,
// with no Tailscale account required. See the tailcat Go package
// documentation for the underlying concepts (ConnBlob, DERP regions,
// the meow handshake).
//
// Concurrency: all functions are safe to call from any thread.
//
// Connections and listeners are file descriptors (one end of an
// AF_UNIX socketpair; the Go side of the library shuttles bytes
// between them and the encrypted tunnel), so they integrate directly
// with poll/epoll/kqueue event loops. Writing to a connection whose
// peer is gone raises SIGPIPE as usual; callers should ignore SIGPIPE
// or send with MSG_NOSIGNAL.
//
// Errors: unless documented otherwise, functions return 0 on success,
// EBADF if the handle is invalid, ERANGE if an output buffer is too
// small (the buffer is still NUL-terminated), or -1 for other errors
// whose details tailcat_errmsg returns.

#include <stddef.h>

#ifndef TAILCAT_H
#define TAILCAT_H

#ifdef __cplusplus
extern "C" {
#endif

// tailcat_server is a handle onto a tailcat server: the side that
// publishes a connection blob and accepts clients.
typedef int tailcat_server;

// tailcat_client is a handle onto a tailcat client: the side that
// connects to a server identified by a connection blob.
typedef int tailcat_client;

// A tailcat_conn is a connection over the tunnel. It is a socketpair
// end on which you can use read(2), write(2), shutdown(2), and
// close(2). Closing it releases the underlying tunnel connection.
typedef int tailcat_conn;

// A tailcat_listener accepts connections to one TCP port of a server.
// It is a socketpair end that becomes readable when a connection is
// ready to accept (so it can be polled), and connection fds arrive on
// it via SCM_RIGHTS. Use tailcat_accept, and close(2) it when done.
typedef int tailcat_listener;

// tailcat_keypair_new generates a new node private key and writes its
// text form ("privkey:...") to buf. Store it to give a server (or
// client) a stable identity across runs; a server's identity
// determines its connection blob.
//
// Returns 0, ERANGE, or -1 on internal error.
extern int tailcat_keypair_new(char* buf, size_t buflen);

// tailcat_pubkey writes the public key ("nodekey:...") of the given
// private key ("privkey:...") to buf. Servers use clients' public
// keys for access control (not yet exposed in this API).
//
// Returns 0, ERANGE, or -1 if privkey doesn't parse.
extern int tailcat_pubkey(const char* privkey, char* buf, size_t buflen);

// tailcat_server_new creates a server object with the given private
// key ("privkey:..."), or a fresh ephemeral key if privkey is NULL or
// empty. No network activity happens until tailcat_server_start.
//
// Returns the new handle, or 0 on error (bad key or out of fds).
extern tailcat_server tailcat_server_new(const char* privkey);

// tailcat_server_set_derpmap_url sets the URL of the JSON DERP map
// used to resolve or auto-select the server's relay region. If unset,
// the default tailcat DERP map URL is used.
//
// Must be called before tailcat_server_start.
extern int tailcat_server_set_derpmap_url(tailcat_server s, const char* url);

// tailcat_server_set_region_id sets the DERP region the server
// listens on. The default of -1 auto-selects the lowest-latency
// region from the DERP map at start.
//
// Must be called before tailcat_server_start.
extern int tailcat_server_set_region_id(tailcat_server s, int region_id);

// tailcat_server_set_logfd instructs the server to write diagnostic
// logs to fd. An fd of -1 (the default) discards logs.
extern int tailcat_server_set_logfd(tailcat_server s, int fd);

// tailcat_server_start resolves the DERP region (fetching the DERP
// map over the network if needed), connects to the relay, and begins
// accepting clients. It blocks until the server is up or fails.
extern int tailcat_server_start(tailcat_server s);

// tailcat_server_connblob writes the server's connection blob
// ("tc..."), the string clients pass to tailcat_client_new, to buf.
// Only valid after tailcat_server_start.
extern int tailcat_server_connblob(tailcat_server s, char* buf, size_t buflen);

// tailcat_server_listen arranges for connections to the given TCP
// port of the server to be delivered to the new listener written to
// listener_out. It may be called before or after tailcat_server_start.
// Connections to ports with no listener are refused.
//
// Fails if the port already has a listener.
extern int tailcat_server_listen(tailcat_server s, int port, tailcat_listener* listener_out);

// tailcat_accept accepts a connection from a listener, blocking until
// one is available. Poll the listener for readability first to avoid
// blocking. The new connection is written to conn_out.
extern int tailcat_accept(tailcat_listener l, tailcat_conn* conn_out);

// tailcat_server_close shuts down the server: its relay connection,
// its listeners, and its event fd. Established connections get EOF as
// their tunnels tear down.
extern int tailcat_server_close(tailcat_server s);

// tailcat_client_new creates a client that will connect to the server
// identified by connblob ("tc..."), using the given private key
// ("privkey:...") or a fresh ephemeral key if privkey is NULL or
// empty. No network activity happens until the first
// tailcat_client_connect or tailcat_client_dial.
//
// Returns the new handle, or 0 on error (bad blob or key).
extern tailcat_client tailcat_client_new(const char* connblob, const char* privkey);

// tailcat_client_set_derpmap_url sets the URL of the JSON DERP map
// used to resolve the relay region referenced by the connection blob.
// If unset, the default tailcat DERP map URL is used.
//
// Must be called before the client's first connect or dial.
extern int tailcat_client_set_derpmap_url(tailcat_client c, const char* url);

// tailcat_client_set_logfd instructs the client to write diagnostic
// logs to fd. An fd of -1 (the default) discards logs.
extern int tailcat_client_set_logfd(tailcat_client c, int fd);

// tailcat_client_connect establishes the tunnel: it connects to the
// relay and performs the handshake with the server, blocking until
// the server acknowledges the client (internal timeout: 10 seconds).
//
// Calling it is optional (tailcat_client_dial establishes the tunnel
// implicitly) but useful to test connectivity or measure the relay
// round-trip time, written to *latency_ms_out if non-NULL.
extern int tailcat_client_connect(tailcat_client c, double* latency_ms_out);

// tailcat_client_dial opens a connection to the given TCP port on the
// server. It does not block: the connection is written to conn_out
// immediately and the tunnel is established in the background (30
// second timeout). Data written meanwhile is buffered (up to the
// socketpair buffer size, typically ~200 kB; writes beyond that block
// or, on a nonblocking fd, fail with EAGAIN).
//
// The outcome arrives as a "dial-ok" or "dial-error" event naming
// this connection (see tailcat_events_fd). On failure the connection
// also reads EOF. Callers that don't watch events can simply treat
// EOF-before-any-data as a failed dial.
extern int tailcat_client_dial(tailcat_client c, int port, tailcat_conn* conn_out);

// tailcat_client_close shuts down the client, its tunnel, and its
// event fd. Open connections get EOF.
extern int tailcat_client_close(tailcat_client c);

// tailcat_events_fd returns the event fd of a server or client
// handle, or -1 if the handle is invalid. The fd becomes readable
// when events are pending; it reads EOF once the handle is closed.
// Bytes on it are wakeup hints, not event counts: when it is
// readable, read and discard the available bytes, then call
// tailcat_event_next until it returns EAGAIN. Don't close this fd
// before the handle is closed; after that, the caller may close it.
extern int tailcat_events_fd(int handle);

// tailcat_event_next pops the next pending event of a server or
// client handle into buf as a JSON object with a "type" field:
//
//   {"type":"client-connected","key":"nodekey:..."}  (server)
//       A new client completed the handshake and can now dial.
//   {"type":"connected"}  (client)
//       The server acknowledged this client; the tunnel is ready.
//   {"type":"dial-ok","conn":<fd>}  (client)
//       The dial that returned connection <fd> succeeded.
//   {"type":"dial-error","conn":<fd>,"err":"..."}  (client)
//       The dial that returned connection <fd> failed.
//
// More event types may be added; ignore unknown types. A buffer of
// 512 bytes is sufficient for all current events.
//
// Returns 0, EAGAIN if no event is pending, EBADF, or ERANGE (the
// event is not consumed; retry with a bigger buffer).
extern int tailcat_event_next(int handle, char* buf, size_t buflen);

// tailcat_errmsg writes the details of the handle's last error to
// buf. After returning, buf is always NUL-terminated.
//
// Returns 0, EBADF, or ERANGE.
extern int tailcat_errmsg(int handle, char* buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif // TAILCAT_H
