// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import TailcatKit
import XCTest

/// Offline tests of ConnectionToken, TokenInfo and NodePublicKey.
final class TokenTests: XCTestCase {
    /// The token in the README, referencing DERP region 302.
    static let readmeToken = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"
    /// The same server's resolved token, with the relay embedded.
    static let resolvedToken = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA"
    static let readmeKey = "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"

    func testParseReadmeToken() throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: Self.readmeToken))
        XCTAssertEqual(token.rawValue, Self.readmeToken)
        XCTAssertEqual(token.description, Self.readmeToken)
        let info = try token.parse()
        XCTAssertEqual(info.serverPublicKey.rawValue, Self.readmeKey)
        XCTAssertEqual(info.regionID, 302)
        XCTAssertEqual(info.relayHosts, [])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: info.json) as? [String: Any])
        XCTAssertEqual(json["RegionID"] as? Int, 302)
        XCTAssertEqual(json["ServerPublic"] as? String, Self.readmeKey)
    }

    func testParseResolvedToken() throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: Self.resolvedToken))
        let info = try token.parse()
        XCTAssertEqual(info.serverPublicKey.rawValue, Self.readmeKey)
        XCTAssertNil(info.regionID)
        XCTAssertEqual(info.relayHosts, ["tc302a.ipn.dev"])
    }

    func testInvalidPrefixIsNil() {
        XCTAssertNil(ConnectionToken(rawValue: "nope"))
        XCTAssertNil(ConnectionToken(rawValue: ""))
        XCTAssertNil(ConnectionToken(rawValue: "tc"))
        XCTAssertNotNil(ConnectionToken(rawValue: "tcx"))
    }

    func testGarbageThrowsInvalidToken() throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: "tcgarbage"))
        XCTAssertThrowsError(try token.parse()) { error in
            guard case TailcatError.invalidToken(let message) = error else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertFalse(message.isEmpty)
        }
    }

    func testTokenCodable() throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: Self.readmeToken))
        let encoded = try JSONEncoder().encode([token])
        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "[\"\(Self.readmeToken)\"]")
        let decoded = try JSONDecoder().decode([ConnectionToken].self, from: encoded)
        XCTAssertEqual(decoded, [token])
        XCTAssertThrowsError(try JSONDecoder().decode(ConnectionToken.self, from: Data("\"nope\"".utf8)))
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

    func testClientRejectsMalformedToken() throws {
        let token = try XCTUnwrap(ConnectionToken(rawValue: "tcgarbage"))
        XCTAssertThrowsError(try TailcatClient(token: token)) { error in
            guard case TailcatError.invalidToken = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }
}
