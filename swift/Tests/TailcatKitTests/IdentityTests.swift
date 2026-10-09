// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import Testing
import TailcatKit

struct IdentityTests {
    @Test func generateAndRoundTrip() throws {
        let identity = try Identity.generate()
        let json = try #require(JSONSerialization.jsonObject(with: Data(identity.json.utf8)) as? [String: String])
        #expect(json["private_key"]?.hasPrefix("privkey:") == true)
        #expect(json["preshared_key"] != nil)
        #expect(json["public_key"] == identity.publicKey.rawValue)
        #expect(try Identity.generate().publicKey != identity.publicKey)
        #expect(try Identity(json: identity.json) == identity)
        #expect(try JSONDecoder().decode(Identity.self, from: JSONEncoder().encode(identity)) == identity)
    }

    @Test(arguments: ["{}", "not json", "{\"Private\":\"old CLI format\"}"])
    func rejectsInvalidBundle(_ json: String) {
        #expect(throws: TailcatError.self) { try Identity(json: json) }
    }

    @Test func rejectsMismatchedPublicKey() throws {
        let identity = try Identity.generate()
        var json = try #require(JSONSerialization.jsonObject(with: Data(identity.json.utf8)) as? [String: String])
        json["public_key"] = try Identity.generate().publicKey.rawValue
        #expect(throws: TailcatError.self) {
            try Identity(json: String(decoding: JSONEncoder().encode(json), as: UTF8.self))
        }
    }

    @Test func rejectsInvalidSecretWithoutEchoingIt() throws {
        let identity = try Identity.generate()
        var json = try #require(JSONSerialization.jsonObject(with: Data(identity.json.utf8)) as? [String: String])
        json["private_key"] = "invalid-secret-value"
        do {
            _ = try Identity(json: String(decoding: JSONEncoder().encode(json), as: UTF8.self))
            Issue.record("invalid key accepted")
        } catch {
            #expect(!String(describing: error).contains("invalid-secret-value"))
        }
    }
}
