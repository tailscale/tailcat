// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import TailcatKit
import XCTest

/// Offline tests of TailcatAddress, AddressInfo and NodePublicKey.
final class AddressTests: XCTestCase {
    /// The address in the README, referencing DERP region 302.
    static let readmeAddress = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"
    /// The same server's resolved address, with the relay embedded.
    static let resolvedAddress = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA"
    static let readmeKey = "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"

    func testParseReadmeAddress() throws {
        let address = try XCTUnwrap(TailcatAddress(rawValue: Self.readmeAddress))
        XCTAssertEqual(address.rawValue, Self.readmeAddress)
        XCTAssertEqual(address.description, Self.readmeAddress)
        let info = try address.parse()
        XCTAssertEqual(info.serverPublicKey.rawValue, Self.readmeKey)
        XCTAssertEqual(info.regionID, 302)
        XCTAssertEqual(info.relayHosts, [])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: info.json) as? [String: Any])
        XCTAssertEqual(json["RegionID"] as? Int, 302)
        XCTAssertEqual(json["ServerPublic"] as? String, Self.readmeKey)
    }

    func testParseResolvedAddress() throws {
        let address = try XCTUnwrap(TailcatAddress(rawValue: Self.resolvedAddress))
        let info = try address.parse()
        XCTAssertEqual(info.serverPublicKey.rawValue, Self.readmeKey)
        XCTAssertNil(info.regionID)
        XCTAssertEqual(info.relayHosts, ["tc302a.ipn.dev"])
    }

    func testInvalidPrefixIsNil() {
        XCTAssertNil(TailcatAddress(rawValue: "nope"))
        XCTAssertNil(TailcatAddress(rawValue: ""))
        XCTAssertNil(TailcatAddress(rawValue: "tc"))
        XCTAssertNotNil(TailcatAddress(rawValue: "tcx"))
    }

    func testGarbageThrowsInvalidAddress() throws {
        let address = try XCTUnwrap(TailcatAddress(rawValue: "tcgarbage"))
        XCTAssertThrowsError(try address.parse()) { error in
            guard case TailcatError.invalidAddress(let message) = error else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertFalse(message.isEmpty)
        }
    }

    func testAddressCodable() throws {
        let address = try XCTUnwrap(TailcatAddress(rawValue: Self.readmeAddress))
        let encoded = try JSONEncoder().encode([address])
        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "[\"\(Self.readmeAddress)\"]")
        let decoded = try JSONDecoder().decode([TailcatAddress].self, from: encoded)
        XCTAssertEqual(decoded, [address])
        XCTAssertThrowsError(try JSONDecoder().decode(TailcatAddress.self, from: Data("\"nope\"".utf8)))
    }

    func testNodePublicKeyValidation() throws {
        let key = try XCTUnwrap(NodePublicKey(rawValue: Self.readmeKey))
        XCTAssertEqual(key.rawValue, Self.readmeKey)
        XCTAssertEqual(key.description, Self.readmeKey)
        XCTAssertNil(NodePublicKey(rawValue: "9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"))
        XCTAssertNil(NodePublicKey(rawValue: "nodekey:9c8d2e67"))
        XCTAssertNil(NodePublicKey(rawValue: "nodekey:" + String(repeating: "g", count: 64)))
        XCTAssertNotNil(NodePublicKey(rawValue: "nodekey:" + String(repeating: "A", count: 64)))
        let encoded = try JSONEncoder().encode([key])
        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "[\"\(Self.readmeKey)\"]")
        XCTAssertEqual(try JSONDecoder().decode([NodePublicKey].self, from: encoded), [key])
    }

    /// A DERP map that cannot be fetched is a network failure, not a bad
    /// address: only a malformed address is reported as invalidAddress.
    func testResolveMapsNetworkFailures() async throws {
        // Nothing listens on port 9 of the loopback interface, so the
        // fetch is refused outright.
        let refused = try XCTUnwrap(URL(string: "http://127.0.0.1:9/derpmap.json"))
        let address = try XCTUnwrap(TailcatAddress(rawValue: Self.readmeAddress))
        do {
            _ = try await address.resolved(derpMapURL: refused, timeout: .seconds(5))
            XCTFail("resolving against a refused DERP map URL succeeded")
        } catch TailcatError.invalidAddress(let message) {
            XCTFail("a network failure was reported as an invalid address: \(message)")
        } catch let error as TailcatError {
            if case .posix(let code, _) = error {
                XCTAssertEqual(code, ECONNREFUSED)
            }
        }
        // A malformed address is invalid whatever the map.
        let garbage = try XCTUnwrap(TailcatAddress(rawValue: "tcgarbage"))
        do {
            _ = try await garbage.resolved(derpMapURL: refused, timeout: .seconds(5))
            XCTFail("resolving a malformed address succeeded")
        } catch TailcatError.invalidAddress {
        }
        // An address that embeds its relay resolves to itself, offline.
        let embedded = try XCTUnwrap(TailcatAddress(rawValue: Self.resolvedAddress))
        let same = try await embedded.resolved(derpMapURL: refused, timeout: .seconds(5))
        XCTAssertEqual(same, embedded)
    }

    func testClientRejectsMalformedAddress() throws {
        let address = try XCTUnwrap(TailcatAddress(rawValue: "tcgarbage"))
        XCTAssertThrowsError(try TailcatClient(address: address)) { error in
            guard case TailcatError.invalidAddress = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }
}
