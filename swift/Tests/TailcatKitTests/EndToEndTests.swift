// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Testing
@testable import TailcatKit

/// make test supplies a local DERP/STUN relay, so these tests need no public
/// service. Running swift test directly still exercises all offline value tests.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["TAILCAT_TEST_REGION"] != nil))
struct LocalRelayTests {
    static func server() throws -> TailcatServer {
        let json = ProcessInfo.processInfo.environment["TAILCAT_TEST_REGION"]!
        return try TailcatServer(configuration: .init(relay: .custom(Data(json.utf8))))
    }

    static func withPair(_ body: @Sendable (TailcatServer, TailcatClient, Listener, Connection, Connection) async throws -> Void) async throws {
        let server = try server()
        let listener: Listener
        let client: TailcatClient
        do {
            listener = try await server.listen(on: 0)
            let address = try await server.start()
            client = try TailcatClient(address: address, derpMapURL: URL(string: "none"))
        } catch { await server.close(); throw error }
        do {
            let outgoing = try await client.connect(port: listener.port)
            let incoming = try await listener.accept(timeout: .seconds(10))
            try await body(server, client, listener, outgoing, incoming)
        } catch {
            await client.close(); await server.close()
            throw error
        }
        await client.close(); await server.close()
    }

    @Test func roundTripHalfCloseAndOwnership() async throws {
        try await Self.withPair { server, client, listener, outgoing, incoming in
            #expect(listener.port > 0)
            #expect(incoming.localPort == listener.port)
            #expect(outgoing.remoteAddress != nil)
            #expect(try await server.start() == server.address)
            let address = try #require(await server.address)
            #expect(try address.parse().serverPublicKey == server.publicKey)
            #expect(try await client.ping() >= .zero)
            let path = try await client.path()
            #expect(path.isDirect || path.relayRegionCode != nil)
            // Accepted streams survive listener closure.
            await listener.close()
            try await outgoing.send(Data("hello".utf8))
            try await outgoing.closeWrite()
            var request = Data()
            for try await bytes in incoming.incoming { request.append(bytes) }
            #expect(request == Data("hello".utf8))
            try await incoming.send(Data("WORLD".utf8))
            try await incoming.closeWrite()
            var reply = Data()
            for try await bytes in outgoing.incoming { reply.append(bytes) }
            #expect(reply == Data("WORLD".utf8))
            #expect(try await outgoing.receive().isEmpty)
            await outgoing.close(); await incoming.close()
            try await client.drain()
        }
    }

    @Test func receiveCancellationTimeoutAndReuse() async throws {
        try await Self.withPair { _, _, _, outgoing, incoming in
            for index in 0..<60 {
                let waiting = Task { try await incoming.receive() }
                if index % 3 == 1 { await Task.yield() }
                if index % 3 == 2 { try await Task.sleep(for: .milliseconds(1)) }
                waiting.cancel()
                do { _ = try await waiting.value; Issue.record("cancelled read succeeded") }
                catch { #expect(error is CancellationError) }
            }
            do {
                _ = try await incoming.receive(timeout: .milliseconds(20))
                Issue.record("idle read did not time out")
            } catch { #expect(error as? TailcatError == .timeout) }
            try await outgoing.send(Data("abcdef".utf8))
            #expect(try await incoming.receive(maxLength: 2) == Data("ab".utf8))
            #expect(try await incoming.receive(maxLength: 4) == Data("cdef".utf8))
        }
    }

    @Test func overlappingReadIsRejectedWithoutDisturbingFirst() async throws {
        try await Self.withPair { _, _, _, outgoing, incoming in
            let first = Task { try await incoming.receive() }
            try await Task.sleep(for: .milliseconds(20))
            do {
                _ = try await incoming.receive(timeout: .milliseconds(10))
                Issue.record("overlapping receive succeeded")
            } catch {
                guard case TailcatError.invalidArgument = error else { throw error }
            }
            try await outgoing.send(Data("a".utf8))
            #expect(try await first.value == Data("a".utf8))
        }
    }

    @Test func closeWakesReadAndRetiresChildren() async throws {
        try await Self.withPair { server, _, listener, _, incoming in
            let reading = Task { try await incoming.receive() }
            let accepting = Task { try await listener.accept() }
            try await Task.sleep(for: .milliseconds(20))
            await server.close()
            do { _ = try await reading.value; Issue.record("read after server close succeeded") }
            catch { #expect(error as? TailcatError == .closed) }
            do { _ = try await accepting.value; Issue.record("accept after server close succeeded") }
            catch { #expect(error as? TailcatError == .closed) }
            await incoming.close(); await incoming.close()
        }
    }

    @Test func acceptCancellationTimeoutAndReuse() async throws {
        let server = try Self.server()
        do {
            let listener = try await server.listen(on: 0)
            for index in 0..<30 {
                let waiting = Task { try await listener.accept() }
                if index % 2 == 1 { try await Task.sleep(for: .milliseconds(1)) }
                waiting.cancel()
                do { _ = try await waiting.value; Issue.record("cancelled accept succeeded") }
                catch { #expect(error is CancellationError) }
            }
            do {
                _ = try await listener.accept(timeout: .milliseconds(20))
                Issue.record("idle accept did not time out")
            } catch { #expect(error as? TailcatError == .timeout) }
            let address = try await server.start()
            let client = try TailcatClient(address: address, derpMapURL: URL(string: "none"))
            do {
                let outgoing = try await client.connect(port: listener.port)
                let incoming = try await listener.accept(timeout: .seconds(5))
                await outgoing.close(); await incoming.close()
            } catch { await client.close(); throw error }
            await client.close()
            let waiting = Task { try await listener.accept() }
            await listener.close()
            do { _ = try await waiting.value; Issue.record("accept after close succeeded") }
            catch { #expect(error as? TailcatError == .closed) }
            let again = try await server.listen(on: listener.port)
            #expect(again.port == listener.port)
        } catch { await server.close(); throw error }
        await server.close()
    }

    @Test func largeSendAndPartialWriteTimeout() async throws {
        try await Self.withPair { _, _, _, outgoing, incoming in
            let payload = Data(repeating: 42, count: 1_000_000)
            let reading = Task {
                var received = Data()
                while received.count < payload.count {
                    let bytes = try await incoming.receive(timeout: .seconds(10))
                    if bytes.isEmpty { break }
                    received.append(bytes)
                }
                return received
            }
            try await outgoing.send(payload, timeout: .seconds(10))
            #expect(try await reading.value == payload)
            do {
                // No receiver drains this write, so TCP backpressure exceeds
                // the deadline after a prefix has been transmitted.
                try await outgoing.send(Data(repeating: 7, count: 16_000_000), timeout: .milliseconds(100))
                Issue.record("backpressured write succeeded")
            } catch let error as PartialWriteError {
                #expect(error.bytesWritten > 0)
                #expect(error.bytesWritten < 16_000_000)
                #expect(error.underlyingError as? TailcatError == .timeout)
            }
        }
    }

    @Test func sendCancellationAndOverlappingWrites() async throws {
        try await Self.withPair { _, _, _, outgoing, incoming in
            let sending = Task { try await outgoing.send(Data(repeating: 9, count: 16_000_000)) }
            // Receiving the first byte proves the large send is in flight.
            #expect(try await incoming.receive(maxLength: 1, timeout: .seconds(5)) == Data([9]))
            do {
                try await outgoing.send(Data([10]))
                Issue.record("overlapping send succeeded")
            } catch {
                guard case TailcatError.invalidArgument = error else { throw error }
            }
            do {
                try await outgoing.closeWrite()
                Issue.record("overlapping half-close succeeded")
            } catch {
                guard case TailcatError.invalidArgument = error else { throw error }
            }
            sending.cancel()
            var bytesWritten = 0
            do { try await sending.value; Issue.record("cancelled send succeeded") }
            catch let error as PartialWriteError {
                bytesWritten = error.bytesWritten
                #expect(error.underlyingError is CancellationError)
            }
            #expect(bytesWritten > 0 && bytesWritten < 16_000_000)
            var received = 1
            while received < bytesWritten {
                let chunk = try await incoming.receive(maxLength: min(65_536, bytesWritten - received), timeout: .seconds(5))
                #expect(!chunk.isEmpty)
                if chunk.isEmpty { break }
                received += chunk.count
            }
            #expect(received == bytesWritten)
            try await outgoing.send(Data([11]))
            #expect(try await incoming.receive(maxLength: 1, timeout: .seconds(5)) == Data([11]))
        }
    }

    @Test func clientIdentityAndExpiredOperations() async throws {
        let server = try Self.server()
        do {
            let address = try await server.start()
            let identity = try Identity.generate()
            let client = try TailcatClient(address: address, identity: identity, derpMapURL: URL(string: "none"))
            do {
                #expect(try await client.publicKey == identity.publicKey)
                do { _ = try await client.connect(port: 0); Issue.record("zero dial port accepted") }
                catch { #expect(error as? TailcatError == .invalidPort) }
                do { _ = try await client.ping(timeout: .zero); Issue.record("expired ping succeeded") }
                catch { #expect(error as? TailcatError == .timeout) }
                #expect(try await client.ping() >= .zero)
            } catch { await client.close(); throw error }
            await client.close()
        } catch { await server.close(); throw error }
        await server.close()
    }
}
