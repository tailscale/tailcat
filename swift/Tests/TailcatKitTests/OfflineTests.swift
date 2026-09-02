// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
@testable import TailcatKit
import XCTest

/// Writes text to the raw peer descriptor of a test socketpair.
func peerWrite(_ fd: Int32, _ text: String) {
    let data = Data(text.utf8)
    let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    XCTAssertEqual(n, data.count)
}

/// Reads up to max bytes from the raw peer descriptor; nil on error.
func peerRead(_ fd: Int32, max: Int = 4096) -> Data? {
    var buf = [UInt8](repeating: 0, count: max)
    let n = Darwin.read(fd, &buf, max)
    return n < 0 ? nil : Data(buf[0..<n])
}

/// Offline tests of Connection over a plain socketpair, and of the server
/// and listener life cycle before start.
final class ConnectionTests: XCTestCase {
    /// A Connection and the raw descriptor of its peer.
    func makePair() throws -> (Connection, Int32) {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        var one: Int32 = 1
        setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return (Connection(fd: fds[0], remoteAddress: "peer", localPort: 1), fds[1])
    }

    func testReceiveReturnsWhatIsAvailable() async throws {
        let (conn, peer) = try makePair()
        defer { Darwin.close(peer) }
        XCTAssertEqual(conn.remoteAddress, "peer")
        XCTAssertEqual(conn.localPort, 1)
        peerWrite(peer, "hello")
        // Does not wait for maxLength bytes.
        let got = try await conn.receive(maxLength: 65_536)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "hello")
        conn.close()
    }

    func testReceiveHonorsMaxLength() async throws {
        let (conn, peer) = try makePair()
        defer { Darwin.close(peer) }
        peerWrite(peer, "abcdef")
        let first = try await conn.receive(maxLength: 2)
        XCTAssertEqual(String(decoding: first, as: UTF8.self), "ab")
        let rest = try await conn.receive(maxLength: 10)
        XCTAssertEqual(String(decoding: rest, as: UTF8.self), "cdef")
        conn.close()
    }

    func testEOFReturnsEmpty() async throws {
        let (conn, peer) = try makePair()
        peerWrite(peer, "bye")
        Darwin.shutdown(peer, SHUT_WR)
        let got = try await conn.receive()
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "bye")
        let eof = try await conn.receive()
        XCTAssertTrue(eof.isEmpty)
        let again = try await conn.receive()
        XCTAssertTrue(again.isEmpty)
        // Writes still flow after the peer's half-close.
        try await conn.send(Data("still here".utf8))
        XCTAssertEqual(peerRead(peer), Data("still here".utf8))
        conn.close()
        Darwin.close(peer)
    }

    func testSendAndCloseWrite() async throws {
        let (conn, peer) = try makePair()
        try await conn.send(Data("ping".utf8))
        XCTAssertEqual(peerRead(peer), Data("ping".utf8))
        try await conn.send(Data())
        conn.closeWrite()
        conn.closeWrite()
        XCTAssertEqual(peerRead(peer), Data())
        // Reads still work after our half-close.
        peerWrite(peer, "pong")
        let got = try await conn.receive()
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "pong")
        // And sending fails now that writing is shut down.
        do {
            try await conn.send(Data("late".utf8))
            XCTFail("send after closeWrite succeeded")
        } catch TailcatError.posix(let code, _) {
            XCTAssertEqual(code, EPIPE)
        }
        conn.close()
        Darwin.close(peer)
    }

    func testIncomingStream() async throws {
        let (conn, peer) = try makePair()
        let writer = Thread {
            for i in 0..<20 {
                peerWrite(peer, "chunk \(i)\n")
                usleep(2_000)
            }
            Darwin.shutdown(peer, SHUT_WR)
        }
        writer.start()
        var all = Data()
        for try await chunk in conn.incoming {
            all.append(chunk)
        }
        let want = (0..<20).map { "chunk \($0)\n" }.joined()
        XCTAssertEqual(String(decoding: all, as: UTF8.self), want)
        conn.close()
        Darwin.close(peer)
    }

    func testCloseWakesReceiver() async throws {
        let (conn, peer) = try makePair()
        defer { Darwin.close(peer) }
        let waiting = Task { try await conn.receive() }
        try await Task.sleep(for: .milliseconds(50))
        conn.close()
        do {
            _ = try await waiting.value
            XCTFail("receive returned after close")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        // Closing is idempotent and later calls fail cleanly.
        conn.close()
        do {
            _ = try await conn.receive()
            XCTFail("receive after close succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        do {
            try await conn.send(Data("x".utf8))
            XCTFail("send after close succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        // The peer sees EOF once the descriptor is closed.
        XCTAssertEqual(peerRead(peer), Data())
    }

    func testCancellationLeavesDataForNextReceive() async throws {
        let (conn, peer) = try makePair()
        let waiting = Task { try await conn.receive() }
        try await Task.sleep(for: .milliseconds(50))
        waiting.cancel()
        do {
            _ = try await waiting.value
            XCTFail("receive returned after cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "unexpected error \(error)")
        }
        peerWrite(peer, "later")
        let got = try await conn.receive()
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "later")
        conn.close()
        Darwin.close(peer)
    }

    func testDeinitClosesDescriptor() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        do {
            let conn = Connection(fd: fds[0], remoteAddress: nil, localPort: nil)
            XCTAssertNil(conn.remoteAddress)
            XCTAssertNil(conn.localPort)
        }
        // DispatchIO closes the descriptor asynchronously; the peer then
        // reads EOF.
        var pfd = pollfd(fd: fds[1], events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&pfd, 1, 5000), 1)
        XCTAssertEqual(peerRead(fds[1]), Data())
        Darwin.close(fds[1])
    }
}

final class ServerLifecycleTests: XCTestCase {
    func testConfigurationDefaults() {
        let config = ServerConfiguration()
        XCTAssertNil(config.identity)
        XCTAssertEqual(config.relay, .automatic)
        XCTAssertNil(config.derpMapURL)
        XCTAssertFalse(config.embedRelayInToken)
        XCTAssertEqual(config.allowedClients, [])
        let custom = ServerConfiguration(relay: .region(302), embedRelayInToken: true)
        XCTAssertEqual(custom.relay, .region(302))
        XCTAssertTrue(custom.embedRelayInToken)
    }

    func testServerBeforeStart() async throws {
        let identity = try Identity.generate()
        let server = try TailcatServer(configuration: .init(identity: identity, relay: .region(302), allowedClients: [identity.publicKey]))
        XCTAssertEqual(server.publicKey, identity.publicKey)
        let token = await server.token
        XCTAssertNil(token)
        do {
            _ = try await server.status()
            XCTFail("status before start succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .notStarted)
        }
        let listener = try await server.listen(on: 80)
        XCTAssertEqual(listener.port, 80)
        // A port may be registered once until its listener is closed.
        do {
            _ = try await server.listen(on: 80)
            XCTFail("listening twice on port 80 succeeded")
        } catch TailcatError.internalError(let message) {
            XCTAssertTrue(message.contains("80"), message)
        }
        try await server.allow(try Identity.generate().publicKey)
        let catchAll = try await server.listen(on: 0)
        XCTAssertEqual(catchAll.port, 0)

        // Closing the server ends a waiting accept.
        let accepting = Task { try await listener.accept() }
        try await Task.sleep(for: .milliseconds(50))
        await server.close()
        do {
            _ = try await accepting.value
            XCTFail("accept returned after the server closed")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        await server.close()
        do {
            _ = try await server.start()
            XCTFail("start after close succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        await listener.close()
        await catchAll.close()
        do {
            _ = try await catchAll.accept()
            XCTFail("accept after close succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
    }

    func testListenerCloseWakesAccept() async throws {
        let server = try TailcatServer()
        let listener = try await server.listen(on: 8080)
        let accepting = Task { try await listener.accept() }
        try await Task.sleep(for: .milliseconds(50))
        await listener.close()
        do {
            _ = try await accepting.value
            XCTFail("accept returned after the listener closed")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        // The port is free again.
        let again = try await server.listen(on: 8080)
        XCTAssertEqual(again.port, 8080)
        await again.close()
        await server.close()
    }

    func testConnectionsStreamEndsOnClose() async throws {
        let server = try TailcatServer()
        let listener = try await server.listen(on: 9000)
        let consuming = Task { () -> Int in
            var count = 0
            for try await _ in listener.connections {
                count += 1
            }
            return count
        }
        try await Task.sleep(for: .milliseconds(50))
        await listener.close()
        let count = try await consuming.value
        XCTAssertEqual(count, 0)
        await server.close()
    }

    func testAcceptCancellation() async throws {
        let server = try TailcatServer()
        let listener = try await server.listen(on: 9001)
        let accepting = Task { try await listener.accept() }
        try await Task.sleep(for: .milliseconds(50))
        accepting.cancel()
        do {
            _ = try await accepting.value
            XCTFail("accept returned after cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "unexpected error \(error)")
        }
        // The listener is still usable afterwards.
        let again = Task { try await listener.accept() }
        try await Task.sleep(for: .milliseconds(50))
        await listener.close()
        do {
            _ = try await again.value
            XCTFail("accept returned after close")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
        await server.close()
    }

    func testClientBeforeUse() async throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: TokenTests.readmeToken))
        let identity = try Identity.generate()
        let client = try TailcatClient(token: token, identity: identity, derpMapURL: URL(string: "https://example.invalid/derpmap.json"))
        XCTAssertEqual(client.token, token)
        let key = try await client.publicKey
        XCTAssertEqual(key, identity.publicKey)
        do {
            _ = try await client.connect(port: 0)
            XCTFail("connect to port 0 succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .invalidPort)
        }
        await client.close()
        await client.close()
        do {
            _ = try await client.ping()
            XCTFail("ping after close succeeded")
        } catch {
            XCTAssertEqual(error as? TailcatError, .closed)
        }
    }
}
