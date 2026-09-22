# libtailcat C API

Build the shared library and generated linker header from the Tailcat module:

```sh
CGO_ENABLED=1 go build -buildmode=c-shared -o libtailcat.so ./cmd/libtailcat
```

Use `.dylib` on macOS and `.dll` on Windows. A C compiler and the Go toolchain
specified by `go.mod` are required. Production builds should use the tags in
`build-tags.txt`. `tailcat.h` is the public ABI definition; the generated
`libtailcat.h` is a build artifact. ABI version 1 is returned by `tc_abi_version`.

## Ownership and errors

All handles are opaque 64-bit integers. Zero is invalid as a resource handle;
only token arguments accept it as the `TC_NO_CANCEL` sentinel. A handle is
never reused within a process. Handles are checked for existence and resource type.
`tc_close` retires a handle, interrupts active calls, and releases its resources.
Calling it on a retired handle returns `TC_CLOSED`.

Clients and servers own their connections. Servers also own listeners. Accepted
connections are children of the server: closing a listener does not close its
accepted connections. Closing a client/server closes its complete resource tree.
An active function retains its Go objects until it returns, even during close.

Every fallible function returns a `TC_*` status and optionally writes an allocated
UTF-8 error string through `char **error`. Every returned string, including JSON,
must be released with `tc_free`. Output string/handle pointers must be non-null;
the error pointer may be null. Inputs are borrowed for the duration of the call.
Strings are NUL-terminated UTF-8. Input pointers must identify valid memory.
No function retains caller buffers or returns pointers into Go memory.

`tc_conn_read` and `tc_conn_write` always set their byte count, including on error.
Process those bytes before the error. TCP EOF is `TC_EOF`; a zero-length UDP
packet is `TC_OK` with count zero. UDP writes above 1232 bytes are rejected.
Read/write calls may be partial. One read and one write may proceed concurrently;
same-direction calls are serialized and their queue time counts toward deadlines.

## Tokens and cancellation

All calls are synchronous. If no caller deadline or explicit cancellation is
needed, pass `TC_NO_CANCEL` (zero) as the token argument:

```c
size_t count = 0;
char *error = NULL;
int32_t status = tc_conn_read(connection, TC_NO_CANCEL,
    buffer, sizeof(buffer), &count, &error);
/* Process count bytes, then handle status. */
tc_free(error);
```

This allocates no token and requires no cleanup. Closing the connection, listener,
or owning peer still interrupts its calls, and internal protocol timeouts still
apply. `tc_token_cancel(TC_NO_CANCEL, ...)` and
`tc_close(TC_NO_CANCEL, ...)` return `TC_CLOSED`. Take care with zero-initialized
token variables: passing zero now allows a call to wait indefinitely instead
of reporting an invalid handle.

Create a `tc_token` with `tc_token_new(timeout_ns, ...)`. The timeout begins
at creation; `-1` disables the deadline, zero expires immediately. Pass that handle
to blocking functions, then close it. `tc_token_cancel` is nonblocking and may
run on another thread. Closing a token cancels it too. Cancellation of a
pending accept does not close its listener. Cancellation of read/write interrupts
that direction and leaves the connection available for a later I/O call.

`tc_token_new(-1, ...)` still allocates a cancellable token; it is not the same
as `TC_NO_CANCEL`. Async language wrappers must retain real tokens even when
no timeout is configured, so task cancellation can interrupt their worker threads.

A token cancelled just as a handle-producing call succeeds may still return
a handle: the caller owns and must close that result. Do not free buffers before
the original call returns. `tc_conn_readable` is a non-consuming, nonblocking
TCP probe intended for connection-pool expiry; it reports data, EOF, and errors
as readable. It is not an OS file descriptor or a readiness subscription API.

## Configuration

`tc_client_new` accepts JSON with `address` (required), `key`, and `derp_map_url`.
`tc_server_new` accepts `key`, `preshared_key`, `region`, `region_id`,
`derp_map_url`, `allowed_clients`, and `udp_idle_timeout` (seconds). Unknown
fields and invalid keys are errors. Logging is discarded by default.

Keys use Tailcat/Tailscale text encodings. `tc_key_generate` returns JSON with
`private_key`, `public_key`, and `preshared_key`. Persist both private and pre-shared
keys to preserve server identity across restarts. `region` is a Tailscale
DERPRegion in its JSON encoding, with Go field names such as `RegionID` and
`Nodes`; that encoding is part of ABI version 1. Omitting it uses relay
discovery. The default relay map is Tailcat's public map.

`tc_server_start` is idempotent at the C API layer. Listening also starts a server.
Unknown configuration fields are reported by name; other configuration errors
are generic so that error text never echoes secrets.
Use `TC_TCP` or `TC_UDP` and a numerical port; listen port zero chooses a free port.
`tc_client_dial` connects directly to a service port on the configured peer.

`tc_info` returns JSON specific to the handle: client public key, server address
and public key, listener local address, or connection local/remote addresses.
Server info requires startup. Endpoint strings are in host:port form (IPv6 hosts
are bracketed). `tc_client_ping` writes relay latency to `int32_t *ping_ms` in
whole milliseconds (fractional milliseconds are truncated). `tc_client_disco_ping`
returns JSON with latency in seconds, endpoint, and DERP-region information.
`tc_drain` waits for TCP shutdown
using the supplied token deadline, and is a no-op before startup.

`tc_address_parse` returns public metadata without the pre-shared key.
`tc_address_resolve` embeds relay information in an address. Addresses and generated
private/pre-shared keys are secrets and should not be included in logs.

This shared library embeds a Go runtime. Keep it loaded for the process lifetime;
do not use it after `fork` without `exec`. This ABI exposes network primitives,
not the Tailcat CLI's SSH, file-sharing, or arbitrary forwarding services.
