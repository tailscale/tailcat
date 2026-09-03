// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import TailcatKit
import XCTest

/// A server and a client in one process, rendezvousing over the public
/// relays. Runs only with TAILCAT_E2E=1 in the environment.
final class EndToEndTests: XCTestCase {
    func testServerClientRoundTrip() async throws {
        guard ProcessInfo.processInfo.environment["TAILCAT_E2E"] == "1" else {
            throw XCTSkip("set TAILCAT_E2E=1 to run the end-to-end test over the public relays")
        }
        let started = ContinuousClock.now
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await Self.roundTrip()
            }
            group.addTask {
                try await Task.sleep(for: .seconds(60))
                throw TailcatError.timeout
            }
            try await group.next()
            group.cancelAll()
        }
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(60))
    }

    static func roundTrip() async throws {
        let server = try TailcatServer(configuration: .init(relay: .automatic), logger: BlackholeLogger())
        let listener = try await server.listen(on: 7000)
        let address = try await server.start()
        XCTAssertTrue(address.rawValue.hasPrefix("tc"))
        let kept = await server.address
        XCTAssertEqual(kept, address)
        let info = try address.parse()
        XCTAssertEqual(info.serverPublicKey, server.publicKey)
        XCTAssertNotNil(info.regionID)

        // The server side: accept one connection, echo its bytes
        // uppercased, then expect the client's half-close.
        let serverSide = Task { () -> Bool in
            let connection = try await listener.accept()
            XCTAssertEqual(connection.localPort, 7000)
            XCTAssertNotNil(connection.remoteAddress)
            var request = Data()
            while request.count < 5 {
                let chunk = try await connection.receive()
                if chunk.isEmpty { break }
                request.append(chunk)
            }
            XCTAssertEqual(String(decoding: request, as: UTF8.self), "hello")
            try await connection.send(Data(request.map { $0 >= 0x61 && $0 <= 0x7A ? $0 - 0x20 : $0 }))
            let eof = try await connection.receive()
            connection.close()
            return eof.isEmpty
        }

        let client = try TailcatClient(address: address, logger: BlackholeLogger())
        // The relay connection completes shortly after start() returns,
        // so the first probe may time out.
        var latency: Duration?
        for attempt in 1...6 {
            do {
                latency = try await client.ping(timeout: .seconds(5))
                break
            } catch TailcatError.timeout where attempt < 6 {
                continue
            }
        }
        let rtt = try XCTUnwrap(latency)
        XCTAssertGreaterThan(rtt, .zero)

        let path = try await client.path()
        XCTAssertGreaterThan(path.latency, .zero)
        XCTAssertTrue(path.isDirect || path.relayRegionCode != nil, String(decoding: path.json, as: UTF8.self))
        XCTAssertEqual(path.isDirect, path.endpoint != nil)

        let connection = try await client.connect(port: 7000)
        XCTAssertNil(connection.remoteAddress)
        try await connection.send(Data("hello".utf8))
        var reply = Data()
        while reply.count < 5 {
            let chunk = try await connection.receive()
            if chunk.isEmpty { break }
            reply.append(chunk)
        }
        XCTAssertEqual(String(decoding: reply, as: UTF8.self), "HELLO")

        connection.closeWrite()
        let serverSawEOF = try await serverSide.value
        XCTAssertTrue(serverSawEOF)
        // The server closed its side, so the client reads EOF.
        let tail = try await connection.receive()
        XCTAssertTrue(tail.isEmpty)

        let status = try await server.status()
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: status) as? [String: Any])

        connection.close()
        await client.close()
        await listener.close()
        await server.close()
    }
}
