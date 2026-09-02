// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// tailcat-demo exercises TailcatKit from the command line and doubles as
// the interop check against the Go tailcat CLI.
//
//   tailcat-demo serve <port>            start a server, print its token on stderr,
//                                        echo every connection's bytes back uppercased
//   tailcat-demo connect <token> <port>  ping (print latency and path), connect, send
//                                        stdin, print what comes back until EOF
//   tailcat-demo parse <token>           print the token's contents
//   tailcat-demo genkey                  print a new identity JSON and its public key
//
// Set TAILCAT_VERBOSE=1 to see the Go side's logs on stderr.

import Foundation
import TailcatKit

func note(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func fail(_ message: String) -> Never {
    note("tailcat-demo: \(message)")
    exit(1)
}

func makeLogger() -> any LogSink {
    ProcessInfo.processInfo.environment["TAILCAT_VERBOSE"] == "1" ? DefaultLogger() : BlackholeLogger()
}

func parsePort(_ text: String) -> UInt16 {
    guard let port = UInt16(text) else { fail("invalid port \(text)") }
    return port
}

func parseToken(_ text: String) -> ConnectionToken {
    guard let token = ConnectionToken(rawValue: text) else { fail("invalid token \(text)") }
    return token
}

func milliseconds(_ d: Duration) -> String {
    let (s, attos) = d.components
    return String(format: "%.1fms", Double(s) * 1000 + Double(attos) / 1e15)
}

/// Uppercases ASCII letters, leaving every other byte alone.
func uppercased(_ data: Data) -> Data {
    Data(data.map { $0 >= 0x61 && $0 <= 0x7A ? $0 - 0x20 : $0 })
}

func echo(_ connection: Connection) async {
    note("# connection from \(connection.remoteAddress ?? "?") on port \(connection.localPort.map(String.init) ?? "?")")
    do {
        for try await chunk in connection.incoming {
            try await connection.send(uppercased(chunk))
        }
        connection.closeWrite()
    } catch {
        note("# connection error: \(error)")
    }
    connection.close()
    note("# connection closed")
}

func serve(port: UInt16) async throws {
    let server = try TailcatServer(configuration: .init(), logger: makeLogger())
    let listener = try await server.listen(on: port)
    note("# public key: \(server.publicKey)")
    let token = try await server.start()
    note("# Server listening on port \(port) with new address: \(token)")
    for try await connection in listener.connections {
        Task { await echo(connection) }
    }
}

func connect(token: ConnectionToken, port: UInt16) async throws {
    let client = try TailcatClient(token: token, logger: makeLogger())
    // A server that just started may still be connecting to its relay,
    // in which case the first probe times out; try a few times.
    var latency: Duration?
    for attempt in 1...4 {
        do {
            latency = try await client.ping(timeout: .seconds(5))
            break
        } catch TailcatError.timeout where attempt < 4 {
            note("# ping timed out, retrying")
        }
    }
    guard let latency else { fail("no answer from the server") }
    note("# pong in \(milliseconds(latency)) via the relay")
    let path = try await client.path()
    if path.isDirect {
        note("# direct path via \(path.endpoint ?? "?"), \(milliseconds(path.latency))")
    } else {
        note("# relayed via DERP(\(path.relayRegionCode ?? "?")), \(milliseconds(path.latency))")
    }
    let connection = try await client.connect(port: port)
    note("# connected to port \(port)")
    // stdin is read on a detached task: availableData blocks, which is
    // fine for a command line tool.
    let sender = Task.detached {
        do {
            while true {
                let chunk = FileHandle.standardInput.availableData
                if chunk.isEmpty { break }
                try await connection.send(chunk)
            }
        } catch {
            note("# send error: \(error)")
        }
        connection.closeWrite()
    }
    for try await chunk in connection.incoming {
        FileHandle.standardOutput.write(chunk)
    }
    sender.cancel()
    connection.close()
    await client.close()
}

func parse(token: ConnectionToken) throws {
    let info = try token.parse()
    print("server public key: \(info.serverPublicKey)")
    if let region = info.regionID {
        print("DERP region ID: \(region)")
    }
    if !info.relayHosts.isEmpty {
        print("relay hosts: \(info.relayHosts.joined(separator: ", "))")
    }
    print(String(decoding: info.json, as: UTF8.self))
}

func genkey() throws {
    let identity = try Identity.generate()
    print(identity.json)
    print("public key: \(identity.publicKey)")
}

let args = Array(CommandLine.arguments.dropFirst())
do {
    switch args.first {
    case "serve" where args.count == 2:
        try await serve(port: parsePort(args[1]))
    case "connect" where args.count == 3:
        try await connect(token: parseToken(args[1]), port: parsePort(args[2]))
    case "parse" where args.count == 2:
        try parse(token: parseToken(args[1]))
    case "genkey" where args.count == 1:
        try genkey()
    default:
        note("usage: tailcat-demo serve <port> | connect <token> <port> | parse <token> | genkey")
        exit(2)
    }
} catch {
    fail("\(error)")
}
exit(0)
