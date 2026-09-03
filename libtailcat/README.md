# libtailcat

A C API over the [tailcat](../README.md) Go library, built with
`go build -buildmode=c-archive` for macOS, iOS and the iOS simulator and
packaged as `CTailcat.xcframework` for use from Swift (see `../swift/`,
the TailcatKit package) or plain C.

The API is in [`include/tailcat.h`](include/tailcat.h). The Go side is
`libtailcat.go`; `tailcat.c` maps each `tailcat_*` function to the Go
export of the same name.

## Building

Requires Go (see `../go.mod` for the version) and Xcode with the iOS SDK.

```sh
make xcframework   # ../swift/CTailcat.xcframework (macOS, iOS, iOS simulator)
make macos         # build/libtailcat_macos.a (arm64 + x86_64) only
make test          # offline Go test of the exported functions
make clean
```

All archives are built with the release build tags from
`../build-tags.txt`. The minimum targets are macOS 14 and iOS 17
(`MACOS_TARGET` overrides the former; the iOS minimum is in
`script/clangwrap-*.sh`).

The cgo-generated `build/*.h` headers are build artifacts; only
`include/` ships in the xcframework. Linking the archive needs the
system frameworks the Go runtime uses on Darwin, typically
`CoreFoundation`, `Security` and `libresolv`.

## Using it from C

Every function is safe to call from any thread. Handle functions return
0 on success, `EBADF` for a bad handle, `ERANGE` for a too-small output
buffer and -1 for other errors, whose text `tailcat_errmsg` returns.
Blocking calls (server start, client ping, path, dial, address resolve)
do network work; keep them off UI threads.

A server:

```c
#include <poll.h>
#include <unistd.h>
#include "tailcat.h"

tailcat_handle sd = tailcat_server_new();
tailcat_listener ln;
tailcat_server_listen(sd, 8080, &ln);      // 0 = every port not otherwise listened on
if (tailcat_server_start(sd) != 0) {       // blocks: DERP map, latency check, relay connect
	char err[256];
	tailcat_errmsg(sd, err, sizeof err);
	// ...
}
char addr[512];
tailcat_server_addr(sd, addr, sizeof addr);      // the tailcat address; give this to clients

for (;;) {
	struct pollfd pfd = {.fd = ln, .events = POLLIN};
	poll(&pfd, 1, -1);                     // a connection is queued
	tailcat_conn c;
	if (tailcat_accept(ln, &c) != 0) break;
	char remote[64];
	int port;
	tailcat_conn_info(ln, c, remote, sizeof remote, &port);
	// c is a socket: read(2), write(2), shutdown(2) for half-close, close(2)
}
close(ln);                                 // stops listening on the port
tailcat_server_close(sd);
```

A client:

```c
tailcat_handle cd = tailcat_client_new(addr);    // 0 if the address is malformed
double ms;
tailcat_client_ping(cd, 10000, &ms);       // blocks; brings the tunnel up
tailcat_conn c;
tailcat_client_dial(cd, 8080, 15000, &c);  // TCP to the server's port 8080
write(c, "hello\n", 6);
shutdown(c, SHUT_WR);                      // half-close: the server sees EOF
// read(c, ...) until 0
close(c);
tailcat_client_close(cd);
```

Connections are one end of a socketpair pumped by Go, so they behave like
sockets; on Apple platforms they have `SO_NOSIGPIPE` set. Keys and
addresses can be handled without a handle: `tailcat_key_generate`,
`tailcat_key_public`, `tailcat_key_addr`, `tailcat_addr_parse` and
`tailcat_addr_resolve` return `NULL` or a malloc'd error string, and
their outputs are malloc'd too; `free()` all of them.
