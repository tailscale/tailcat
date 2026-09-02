// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import TailcatKit
import XCTest

/// Offline tests of Identity.
final class IdentityTests: XCTestCase {
    func testGenerate() throws {
        let identity = try Identity.generate()
        XCTAssertTrue(identity.publicKey.rawValue.hasPrefix("nodekey:"))
        XCTAssertEqual(identity.publicKey.rawValue.count, "nodekey:".count + 64)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(identity.json.utf8)) as? [String: Any])
        XCTAssertNotNil(json["Private"])
        let pub = try XCTUnwrap(json["Public"] as? [String: Any])
        XCTAssertEqual(pub["RegionID"] as? Int, -1)
        // Two identities never share a key.
        XCTAssertNotEqual(try Identity.generate().publicKey, identity.publicKey)
    }

    func testTokenNeedsFixedRelay() throws {
        let identity = try Identity.generate()
        XCTAssertThrowsError(try identity.token()) { error in
            XCTAssertEqual(error as? TailcatError, .relayNotFixed)
        }
    }

    func testInvalidJSONThrows() {
        XCTAssertThrowsError(try Identity(json: "{}")) { error in
            guard case TailcatError.invalidKey = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
        XCTAssertThrowsError(try Identity(json: "not json"))
    }

    func testRoundTrip() throws {
        let identity = try Identity.generate()
        let again = try Identity(json: identity.json)
        XCTAssertEqual(again, identity)
        XCTAssertEqual(again.publicKey, identity.publicKey)
        let encoded = try JSONEncoder().encode(identity)
        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "\"" + identity.json.replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\t", with: "\\t").replacingOccurrences(of: "\"", with: "\\\"") + "\"")
        XCTAssertEqual(try JSONDecoder().decode(Identity.self, from: encoded), identity)
        XCTAssertThrowsError(try JSONDecoder().decode(Identity.self, from: Data("\"{}\"".utf8)))
    }

    func testFixedRegionToken() throws {
        // Pin the generated key to region 302 and check the token it
        // yields names that region and this key.
        let identity = try Identity.generate()
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(identity.json.utf8)) as? [String: Any])
        var pub = try XCTUnwrap(json["Public"] as? [String: Any])
        pub["RegionID"] = 302
        json["Public"] = pub
        let pinned = try Identity(json: String(decoding: try JSONSerialization.data(withJSONObject: json), as: UTF8.self))
        XCTAssertEqual(pinned.publicKey, identity.publicKey)
        let token = try pinned.token()
        XCTAssertTrue(token.rawValue.hasPrefix("tc"))
        let info = try token.parse()
        XCTAssertEqual(info.serverPublicKey, identity.publicKey)
        XCTAssertEqual(info.regionID, 302)
        XCTAssertEqual(info.relayHosts, [])
    }
}
