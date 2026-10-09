# TailcatKit

A Swift 6 package wrapping the upstream [libtailcat C API](../cmd/libtailcat/README.md)
for macOS 14+ and iOS 17+. `TailcatServer` and `TailcatClient` expose async TCP
connections through opaque C handles, with Swift task cancellation and deadlines.

## Building

From this directory, with Go and Xcode (including the iOS SDK) installed:

```sh
make xcframework
swift build -c release -Xswiftc -warnings-as-errors
make test
```

The Makefile builds `../cmd/libtailcat` with `-buildmode=c-archive` and the release
tags from `../build-tags.txt`. It copies the upstream `tailcat.h` into the
XCFramework alongside a Swift module map. No separate C implementation is needed.
The framework contains macOS arm64/x86_64, iOS arm64, and simulator arm64/x86_64.

Add the built `swift` directory as a local Swift package dependency in Xcode.
The framework is an ignored build output, so a remote SwiftPM dependency is not
self-contained until binary distribution is added. The package links the Darwin
frameworks and libraries needed by the Go runtime.

## Usage

A server that echoes TCP connections:

```swift
import Foundation
import TailcatKit

let server = try TailcatServer()
let listener = try await server.listen(on: 8080) // starts the server if needed
let address = try await server.start()          // repeated starts succeed
// Share address securely with the client. It grants access to the server.

for try await connection in listener.connections {
    Task {
        do {
            for try await chunk in connection.incoming {
                try await connection.send(chunk)
            }
            try await connection.closeWrite()
        } catch {
            // Handle cancellation or a transport failure.
        }
        await connection.close()
    }
}
```

A client using that address:

```swift
let client = try TailcatClient(address: address)
let connection = try await client.connect(port: 8080)
try await connection.send(Data("hello\n".utf8))
try await connection.closeWrite()
for try await chunk in connection.incoming {
    // Consume the reply. The stream ends at TCP EOF.
}
await connection.close()
try await client.drain(timeout: .seconds(5))
await client.close()
```

`listen(on: 0)` allocates a free port, exposed by `Listener.port`. Closing a
listener leaves accepted connections alive. Closing a server or client retires
all its child handles, interrupts active calls, and waits for teardown on a worker
queue. `close()` is async and idempotent; deinitialization schedules fallback
cleanup on a worker. Prefer explicit close when shutdown completion matters.
`drain` waits for TCP shutdown traffic before the peer is closed.

### Cancellation and I/O

Every blocking operation has its own C token. Swift task cancellation calls
`tc_token_cancel`, including when no timeout is supplied. `timeout: nil` means
no caller deadline; zero or a negative duration expires immediately. Time spent
waiting on a worker queue counts toward the deadline. C buffers and tokens stay
alive until the original synchronous call returns. Completion can win a
cancellation race, in which case the successful result is delivered and owned
normally.

One receive and one send can run concurrently on worker threads. Overlapping
receives, or overlapping sends/`closeWrite` calls, throw `invalidArgument`;
await a send before starting another or half-closing. `receive` returns available
bytes, up to `maxLength`, and empty `Data` at EOF. Cancelling a read or accept
leaves the connection or listener usable. `send` handles short writes under one
deadline. A failure after bytes have been transmitted throws
`PartialWriteError`, including `bytesWritten` and `underlyingError`; do not replay
that prefix. If a read returns both bytes and an error, the bytes are delivered
first and the next receive reports the error.

Errors use C status codes, with messages belonging to the individual operation.
`TC_CANCELLED` becomes `CancellationError`, `TC_TIMEOUT` becomes
`TailcatError.timeout`, and `TC_CLOSED` becomes `TailcatError.closed`.
All C allocations are released with `tc_free`.

### Keys, relays, and diagnostics

```swift
let identity = try Identity.generate()
// Store identity.json in the Keychain, including its private and pre-shared keys.
let server = try TailcatServer(configuration: .init(
    identity: identity,
    relay: .region(302),
    allowedClients: [knownClientKey]
))
let info = try address.parse()       // public metadata only
let resolved = try await address.resolved() // embeds relay details
let latency = try await client.ping() // whole milliseconds; zero is valid
let path = try await client.path()   // direct endpoint or relay region
```

Identity JSON uses the C API's `private_key`, `public_key`, and `preshared_key`
fields. It is distinct from the CLI's key-file format. Restore the complete bundle
to preserve a server's identity and capability. Relay selection belongs to
`ServerConfiguration`, using `.automatic`, `.region(id)`, or `.custom(data)` with
a DERPRegion JSON object. The server's address is available after `start()`.

The allowlist restricts subsequent registration and does not disconnect existing
flows. Configure it before startup when access should be restricted immediately.
Addresses and private/pre-shared keys are secrets. The wrapper never logs them.
`LogSink` receives Swift lifecycle messages; the C API discards Go logs.

### Changes from the original PR API

- The upstream `tc_*` API replaces the private `tailcat_*` layer and socketpairs.
- `listen` starts the server and port zero chooses a free port. There is no
  catch-all listener, and `start` is idempotent.
- `closeWrite` is async and throwing; all resource `close` methods are async.
- Identity JSON uses the C API key bundle. `Identity.address()` is removed;
  obtain addresses from a started server.
- `.hosts` is replaced by `.custom` DERPRegion JSON. The C API controls address
  encoding, so `embedRelayInAddress` is removed.
- The old WireGuard `status()` and Go log descriptor APIs are not exposed by
  the upstream C API. `path`, `ping`, and connection endpoint metadata remain.
- This package wraps TCP. The upstream C API also supports UDP.

## Tests and demo

`make test` uses a Go test fixture to run a local DERP/STUN server for the Swift
test process. It exercises the actual C archive, including half-close, deadlines,
read/accept cancellation and reuse, partial writes, child ownership, keys, and
address helpers, without relying on public relays. `swift test` alone runs the
value/lifecycle tests and skips tests requiring the local relay fixture.

```sh
swift run tailcat-demo serve 7777
swift run tailcat-demo connect <address> 7777
swift run tailcat-demo parse <address>
swift run tailcat-demo genkey
```

The demo prints a secret address for sharing when serving and secret key material
for `genkey`; protect that output. Set `TAILCAT_VERBOSE=1` for Swift lifecycle logs.
The demo interoperates with `go run ./cmd/tailcat <address> 7777` from the repo root.

## iOS compilation

From this directory:

```sh
xcodebuild -scheme TailcatKit -destination 'generic/platform=iOS' -derivedDataPath build/device build CODE_SIGNING_ALLOWED=NO
xcodebuild -scheme TailcatKit -destination 'generic/platform=iOS Simulator' -derivedDataPath build/simulator build CODE_SIGNING_ALLOWED=NO
```
