# TailcatKit

A Swift package wrapping [libtailcat](../libtailcat/README.md), the C API
over the [tailcat](../README.md) Go library, in async/await actors for
macOS 14+ and iOS 17+. A `TailcatServer` announces a connection token;
a `TailcatClient` holding the token dials TCP ports on it; both ends
handle bytes through `Connection`. Swift 6 language mode, strict
concurrency, no Combine.

## Building

Build the Go archives first (Go and Xcode with the iOS SDK required):

```sh
cd ../libtailcat && make xcframework   # writes ./CTailcat.xcframework
cd ../swift
swift build                            # the TailcatKit library and tailcat-demo
swift build -c release
swift test                             # offline tests
TAILCAT_E2E=1 swift test               # plus a server/client round trip over the public relays
```

The package is `swift-tools-version: 6.0`; it declares the binary
target `CTailcat` (the xcframework with slices for macOS arm64/x86_64,
iOS arm64 and the iOS simulator arm64/x86_64), the library `TailcatKit`,
the executable `tailcat-demo` and the tests. Add it to an app as a local
or remote package dependency; the `CoreFoundation` and `Security`
frameworks and `libresolv` the Go runtime needs are linked by the
package.

## Usage

A server that echoes every connection to port 8080:

```swift
import TailcatKit

let server = try TailcatServer(configuration: .init(relay: .automatic), logger: DefaultLogger())
let listener = try await server.listen(on: 8080)   // before or after start; 0 is the catch-all
let token = try await server.start()               // blocks off-thread: DERP map, latency check
print("connect with: \(token)")

for try await connection in listener.connections {
    Task {
        print("from \(connection.remoteAddress ?? "?") on port \(connection.localPort ?? 0)")
        for try await chunk in connection.incoming {   // until the peer's EOF
            try await connection.send(chunk)
        }
        connection.close()
    }
}
```

A client:

```swift
let client = try TailcatClient(token: token)
let rtt = try await client.ping()                  // brings the tunnel up; retry on .timeout right after the server started
let path = try await client.path()                 // direct endpoint or relay region
let connection = try await client.connect(port: 8080)
try await connection.send(Data("hello\n".utf8))
connection.closeWrite()                            // half-close: the server reads EOF
let reply = try await connection.receive()         // empty Data at EOF
connection.close()
await client.close()
```

Keys and tokens need no server or client:

```swift
let identity = try Identity.generate()             // a private key; keep it in the Keychain
identity.publicKey                                 // "nodekey:<hex>", for TailcatServer.allow
let token = ConnectionToken(rawValue: "tc...")!
let info = try token.parse()                       // server key, region ID or relay hosts
let long = try await token.resolved()              // self-contained form, relay details embedded
```

Restrict a server to known clients with `ServerConfiguration.allowedClients`
or `TailcatServer.allow(_:)`, and give clients an `Identity` so their
public key is stable. The allow list gates registration: a client that
registered while it was empty stays connected, so list the clients before
start to lock a server down from the beginning. With a saved identity,
`RelaySelection.automatic`
keeps the relay recorded in the key file (a fixed region keeps the token
stable across restarts); `.region(id)` and `.hosts([...])` override it.

### Notes

- Blocking C calls (server start, ping, path, connect, token resolve)
  run on a dedicated dispatch queue, never on an actor or the
  cooperative pool. Everything else is quick.
- `Connection` is backed by DispatchIO: `receive` returns as soon as
  any bytes are available (up to `maxLength`), `send` completes once the
  data has been handed to the tunnel, `closeWrite` is a TCP half-close,
  and `close` (also run by deinit) closes the descriptor exactly once.
  One receive at a time; `incoming` is a pull-based stream over it.
- `start()` returns once the server is configured, like the tailcat CLI;
  the relay connection completes in the background right after, so a
  client's first `ping` may throw `TailcatError.timeout` and is worth
  retrying.
- Closing a server or client also closes its listeners and connections
  on the Go side: their reads see EOF and their accepts throw
  `TailcatError.closed`. The Swift objects still own their descriptors
  until closed or deinitialized.
- Errors are `TailcatError`; the Go side's message is carried in
  `.internalError`, `.invalidToken` and `.invalidKey`.

## The demo

`tailcat-demo` is a small command line tool and the interop check
against the Go CLI:

```sh
swift run tailcat-demo serve 7777            # prints the token on stderr, echoes bytes back uppercased
swift run tailcat-demo connect <token> 7777  # pings, prints latency and path, pipes stdin, prints the reply
swift run tailcat-demo parse <token>
swift run tailcat-demo genkey
```

Against the Go CLI, in the repository root:

```sh
printf 'hi there\n' | go run ./cmd/tailcat <token> 7777      # prints HI THERE

go run ./cmd/tailcat serve 8080                              # with a local server on 8080
printf 'GET / HTTP/1.0\r\n\r\n' | swift run tailcat-demo connect <token> 8080
```

Set `TAILCAT_VERBOSE=1` to see the Go side's logs.

## iOS

The package builds for iOS devices and the simulator:

```sh
xcodebuild -scheme TailcatKit -destination 'generic/platform=iOS' -derivedDataPath build build CODE_SIGNING_ALLOWED=NO
xcodebuild -scheme TailcatKit -destination 'generic/platform=iOS Simulator' -derivedDataPath build build CODE_SIGNING_ALLOWED=NO
```

Keep `start()`, `ping` and friends off the main actor's critical path
(they are async and run off-thread, but they take seconds), and treat
`Identity.json` as a secret.
