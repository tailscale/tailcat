/*
 * Copyright (c) Tailscale Inc & contributors
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBTAILCAT_H
#define LIBTAILCAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ABI conventions:
 *
 * Threading and deadlines
 *
 * Calls are synchronous, including those taking a token handle. A token supplies
 * cancellation and an optional deadline; it is not a future or job. A thread can
 * cancel it while the calling thread is blocked inside this API.
 * Different handles, and one read plus one write on a connection, may be used
 * concurrently. Same-direction I/O is serialized; queue time counts toward
 * the token deadline.
 *
 * Any token parameter may instead be TC_NO_CANCEL: no caller deadline
 * and no explicit cancellation token. Resource closure still interrupts the
 * call, and internal protocol timeouts still apply.
 *
 * Status codes and error messages
 *
 * Except tc_abi_version and tc_free, functions return a TC_* status. TC_OK means
 * success; TC_EOF marks TCP end-of-stream. error itself may be NULL to discard
 * the message. Otherwise *error is set to NULL on success or to an allocated
 * NUL-terminated UTF-8 copy on failure. This copy is writable, caller-owned
 * memory, NOT borrowed internal storage: release it with tc_free. Branch on
 * status codes, not error text. Free a previous message before reusing its slot.
 *
 * Outputs and ownership
 *
 * out and count pointers are required. Handle/string outputs are initialized
 * to zero/NULL before work begins. Returned strings, including JSON, belong to
 * the caller: release them with tc_free. Release returned handles with tc_close.
 * Handles are opaque, nonzero, type-checked, and never reused in this process.
 * Do not share output storage between concurrent calls.
 *
 * Inputs and cancellation
 *
 * Strings are NUL-terminated UTF-8. Unless stated otherwise, pointers must name
 * valid, non-NULL memory. Inputs are borrowed only until the call returns; no
 * caller buffer is retained and no Go pointer is returned. Even after cancelling,
 * keep buffers/output storage alive until the ORIGINAL call returns. Completion
 * may win a cancellation race; the caller still owns any successful result.
 * Cancellation never rolls back bytes sent or other completed side effects.
 *
 * Process lifetime and secrets
 *
 * The shared library embeds a Go runtime. Keep it loaded for the process lifetime
 * and do not use it after fork without exec. Tailcat addresses and private and
 * pre-shared keys are secrets; do not log them. See README.md for build details.
 */

/* BEGIN CFFI */

typedef uint64_t tc_handle;

/** Cancellation/deadline token; a handle released with tc_close when finished. */
typedef tc_handle tc_token;

/**
 * Use as a token argument for synchronous calls with no caller deadline
 * or explicit cancellation token. No token is allocated or needs releasing.
 *
 * Closing the underlying resource still interrupts the call. Internal protocol
 * timeouts still apply. This is not a valid resource handle: tc_close and
 * tc_token_cancel return TC_CLOSED when passed TC_NO_CANCEL.
 *
 * Unlike this sentinel, tc_token_new(-1, ...) creates a cancellable token
 * with no deadline. A timeout_ns of 0 creates an immediately expired token.
 */
#define TC_NO_CANCEL 0

enum {
    TC_OK = 0,
    TC_INVALID_ARGUMENT = 1,
    TC_CLOSED = 2,
    TC_TIMEOUT = 3,
    TC_CANCELLED = 4,
    TC_FAILURE = 5,
    TC_EOF = 6
};

enum {
    TC_TCP = 1,
    TC_UDP = 2
};

/* Version and build information */

/**
 * Return the C ABI version (currently 1); this call cannot fail.
 */
uint32_t tc_abi_version(void);

/**
 * Return allocated JSON containing abi_version and Go build metadata in *out.
 *
 * No network access is performed. Release *out with tc_free.
 */
int32_t tc_build_info(char **out, char **error);

/* Cancellation and lifetime */

/**
 * Create a cancellation/deadline token in *out without starting any I/O.
 *
 * timeout_ns is nanoseconds from token creation, NOT from each later call:
 * -1 disables the deadline, 0 expires immediately, and values below -1 fail.
 *
 * Multiple calls may share one token/deadline (e.g. a TLS handshake or send loop).
 * Keep it until all such calls return, then release it with tc_close. Tokens do
 * not reset after use or cancellation; create a new token for a fresh deadline.
 *
 * If neither a deadline nor explicit cancellation is needed, pass TC_NO_CANCEL
 * to the I/O function instead of creating a token.
 */
int32_t tc_token_new(int64_t timeout_ns, tc_token *out, char **error);

/**
 * Signal cancellation of work using cancellation_token; safe from another thread.
 *
 * Does not wait for blocked calls to return, close their connections/listeners,
 * or release the token. Interrupted calls normally return TC_CANCELLED, but
 * completion may win the race.
 *
 * Cancelling an already cancelled live token succeeds. Wait for original calls
 * before releasing their buffers/token.
 *
 * TC_NO_CANCEL is not a token; attempting to cancel it returns TC_CLOSED.
 */
int32_t tc_token_cancel(tc_token cancellation_token, char **error);

/**
 * Retire a handle and release its resources; later use returns TC_CLOSED.
 *
 * Clients/servers also close their connections and, for servers, their listeners.
 * Closing a listener leaves accepted connections alive.
 *
 * Closing these resources interrupts and waits for active calls on their retired
 * resource tree; this is synchronous and has no timeout. Closing a token instead
 * cancels/releases it and does NOT join calls using it.
 *
 * Unknown/already-closed handles return TC_CLOSED. Even if shutdown reports
 * another error, the handle is retired.
 *
 * TC_NO_CANCEL has nothing to release; passing it here returns TC_CLOSED.
 */
int32_t tc_close(tc_handle resource, char **error);

/**
 * Free a string/error allocation returned by this API; NULL is a no-op.
 *
 * Do not pass handles, buffers allocated by the caller, or an allocation already
 * freed.
 */
void tc_free(void *allocation);

/* Clients, servers, and listeners */

/**
 * Create a client in *out; network startup is deferred until dialing/pinging.
 *
 * config_json contains required address (secret Tailcat address), optional key
 * (text-encoded private node key; otherwise generated), and derp_map_url (relay-map
 * override). Unknown fields/invalid keys are rejected.
 *
 * The client owns its dialed connections. Release it with tc_close.
 */
int32_t tc_client_new(char *config_json, tc_handle *out, char **error);

/**
 * Create an unstarted server in *out from JSON ({} uses defaults).
 *
 * Optional fields: key (private node key), preshared_key, region, region_id,
 * derp_map_url, allowed_clients (array of public node keys), udp_idle_timeout
 * (nonnegative seconds; zero uses the default).
 *
 * region is a Tailscale DERPRegion in its JSON encoding (Go field names such as
 * RegionID and Nodes). That encoding is part of ABI version 1; fields added to
 * DERPRegion later may be accepted but are not part of this ABI.
 *
 * Omitted keys are generated; an empty allowlist permits clients possessing the
 * address. Unknown fields/invalid keys are rejected.
 *
 * Start/listen performs network startup. Release the server with tc_close.
 */
int32_t tc_server_new(char *config_json, tc_handle *out, char **error);

/**
 * Synchronously dial port (1..65535) on client's configured Tailcat peer.
 *
 * network must be TC_TCP or TC_UDP. Startup/registration and dialing share
 * the token's deadline.
 *
 * *out receives a TCP stream or connected UDP flow owned by client; release it
 * with tc_close. This does not dial arbitrary destinations.
 */
int32_t tc_client_dial(tc_handle client, tc_token cancellation_token,
    uint16_t port, int32_t network, tc_handle *out, char **error);

/**
 * Start server synchronously using cancellation_token.
 *
 * Repeated starts succeed with an active token. Afterwards tc_info can return
 * its shareable secret address. Listening also starts a server automatically.
 */
int32_t tc_server_start(tc_handle server, tc_token cancellation_token,
    char **error);

/**
 * Start server if needed and create a TC_TCP or TC_UDP listener in *out.
 *
 * port == 0 chooses a free port; retrieve it from tc_info's local_address.
 *
 * The server owns the listener. tc_listener_accept receives connections/flows;
 * tc_close stops accepting new ones without closing previously accepted ones.
 */
int32_t tc_server_listen(tc_handle server, tc_token cancellation_token,
    uint16_t port, int32_t network, tc_handle *out, char **error);

/**
 * Wait synchronously for a TCP connection or a new connected UDP flow.
 *
 * *out receives a connection owned by the listener's SERVER, not its listener:
 * it survives listener closure but not server closure.
 *
 * Cancellation/timeout interrupts only this accept, leaving the listener usable.
 * Close a successful result with tc_close even if cancellation raced with its
 * delivery.
 */
int32_t tc_listener_accept(tc_handle listener, tc_token cancellation_token,
    tc_handle *out, char **error);

/* Connection I/O */

/**
 * Read into buffer (capacity bytes), setting *count even when an error occurs.
 *
 * TCP reads may be short; TC_EOF marks end-of-stream. A zero-capacity TCP read
 * succeeds with count zero and is not an EOF probe.
 *
 * For UDP, one call consumes one datagram, truncating it if capacity is too small;
 * an empty datagram returns TC_OK with count zero. buffer may be NULL only when
 * capacity is zero.
 *
 * Process returned bytes before the status. Cancellation/timeout ends this read
 * without closing the connection. The call is synchronous; another thread can
 * interrupt its wait with tc_token_cancel.
 */
int32_t tc_conn_read(tc_handle connection, tc_token cancellation_token,
    void *buffer, size_t capacity, size_t *count, char **error);

/**
 * Write from buffer (length bytes), setting *count even when an error occurs.
 *
 * TCP writes may be short: loop with the same token for one overall deadline.
 * UDP sends one datagram: length must be <=1232; zero sends an empty datagram.
 * buffer may be NULL only when length is zero.
 *
 * Bytes in *count may already have been transmitted on timeout/cancellation;
 * do not blindly replay the buffer.
 *
 * Cancellation leaves the raw connection open, but application protocols may
 * require closing it after partial writes.
 */
int32_t tc_conn_write(tc_handle connection, tc_token cancellation_token,
    void *buffer, size_t length, size_t *count, char **error);

/**
 * Half-close TCP writes (send FIN) while retaining the ability to read.
 *
 * Waits behind pending writes under the token's deadline/cancellation. Does not
 * release the handle; eventually use tc_close. UDP does not support half-close.
 *
 * Return does not guarantee FIN acknowledgment; use tc_drain before peer shutdown.
 */
int32_t tc_conn_close_write(tc_handle connection, tc_token cancellation_token,
    char **error);

/**
 * Probe TCP without consuming bytes or waiting for network data.
 *
 * On TC_OK, *out is 1 for buffered data, EOF, or a pending read error, otherwise
 * 0. A concurrent reader can cause a 0 result without inspecting its data.
 *
 * Intended for idle pool expiry, not a readiness subscription/OS descriptor.
 * UDP is unsupported. Check the status before interpreting *out.
 */
int32_t tc_conn_readable(tc_handle connection, int32_t *out, char **error);

/* Peer information and administration */

/**
 * Return allocated JSON describing resource (not a token) in *out.
 *
 * Client: public_key. Started server: address, local_address, public_key.
 * Listener: local_address, network. Connection: local_address, remote_address,
 * network.
 *
 * Listener/connection endpoints use host:port (IPv6 in brackets), and network is
 * TC_TCP/TC_UDP. Server info fails before startup and contains a secret address
 * afterwards. Release the JSON with tc_free.
 */
int32_t tc_info(tc_handle resource, tc_token cancellation_token,
    char **out, char **error);

/**
 * Start/register client if needed, then ping its peer using cancellation_token.
 *
 * Measure the DERP path and return its round-trip latency in *ping_ms, in whole
 * milliseconds (fractional milliseconds are truncated; zero is valid).
 *
 * ping_ms is required and is initialized to zero before work begins.
 * Tailcat's internal ping timeout may finish before the token's deadline.
 */
int32_t tc_client_ping(tc_handle client, tc_token cancellation_token,
    int32_t *ping_ms, char **error);

/**
 * Start/register client if needed, then probe discovery using cancellation_token.
 *
 * Return allocated JSON in *out with latency (seconds), endpoint, derp_region_id,
 * and derp_region_code. endpoint identifies a direct path; otherwise the DERP
 * fields identify the relay. This ping also triggers direct path discovery.
 *
 * Release the JSON with tc_free. Use a token with a deadline to bound waiting:
 * discovery may wait indefinitely if no pong arrives and TC_NO_CANCEL is used.
 */
int32_t tc_client_disco_ping(tc_handle client, tc_token cancellation_token,
    char **out, char **error);

/**
 * Add a text-encoded public node key to server's allowlist before/after startup.
 *
 * The token bounds waiting for server configuration access. An empty list
 * permits any client possessing the address; the first entry restricts subsequent
 * registration to allowed keys. Does not remove keys or disconnect existing flows.
 */
int32_t tc_server_allow_client(tc_handle server, tc_token cancellation_token,
    char *public_key, char **error);

/**
 * Wait for a client's/server's TCP stack to finish shutdown traffic.
 *
 * Call after closing its connections or reaching EOF, BEFORE closing the peer
 * or exiting. Does not itself close handles/connections; an unstarted peer is a
 * no-op with an active token.
 *
 * Use a finite deadline: absent peers or server-side TCP TIME-WAIT can delay
 * draining. Listener/connection/token handles fail.
 */
int32_t tc_drain(tc_handle resource, tc_token cancellation_token, char **error);

/* Addresses and keys */

/**
 * Parse address locally into allocated public-metadata JSON in *out.
 *
 * Fields: public_key, disco_public_key, has_preshared_key, region_id, regions.
 * Deliberately omits the pre-shared key value. No network/relay lookup occurs.
 * Release *out with tc_free.
 */
int32_t tc_address_parse(char *address, char **out, char **error);

/**
 * Return an allocated ADDRESS string (not JSON) with relay details embedded.
 *
 * May fetch the map using cancellation_token. derp_map_url may be NULL or empty
 * to select the default map. Already self-contained addresses need no lookup.
 *
 * The result pins relay details, avoiding later map discovery (connecting still
 * requires network access). Input is unchanged. Treat *out as secret; free with
 * tc_free.
 */
int32_t tc_address_resolve(tc_token cancellation_token, char *address,
    char *derp_map_url, char **out, char **error);

/**
 * Generate a private/public node-key pair and a random pre-shared key locally.
 *
 * *out receives JSON with private_key, public_key, preshared_key in Tailcat's
 * text encodings. Persist both private_key and preshared_key to preserve a
 * server's identity/capability across restarts.
 *
 * The JSON contains secrets; store securely and free with tc_free. No network
 * access is performed.
 */
int32_t tc_key_generate(char **out, char **error);

/* END CFFI */

#ifdef __cplusplus
}
#endif
#endif
