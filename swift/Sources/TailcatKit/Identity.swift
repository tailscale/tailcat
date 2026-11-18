// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import CryptoKit
import Foundation

/// The C API key bundle, containing private_key, public_key and preshared_key.
/// Store the complete JSON securely to preserve a server's identity/capability.
/// This format is distinct from the CLI's private-key file format.
public struct Identity: Sendable, Codable, Hashable {
    public let json: String
    public let publicKey: NodePublicKey
    let privateKey: String
    let presharedKey: String

    public init(json: String) throws {
        struct Keys: Decodable {
            var private_key: String
            var public_key: String
            var preshared_key: String
        }
        do {
            let keys = try JSONDecoder().decode(Keys.self, from: Data(json.utf8))
            guard let publicKey = NodePublicKey(rawValue: keys.public_key),
                  !keys.private_key.isEmpty, !keys.preshared_key.isEmpty else {
                throw TailcatError.invalidKey("missing or invalid keys")
            }
            // Let the C API validate private keys. Creation performs no network
            // work; an unstarted server has no asynchronous teardown to join.
            let config = try JSONEncoder().encode([
                "key": keys.private_key, "preshared_key": keys.preshared_key,
            ])
            var handle: UInt64 = 0
            try String(decoding: config, as: UTF8.self).withCInput { input in
                try CAPI.check { tc_server_new(input, &handle, $0) }
            }
            _ = tc_close(handle, nil)
            // Check that an imported bundle's advertised key belongs to its
            // private key. CryptoKit uses the same X25519 public-key derivation.
            let hex = Array(keys.private_key.dropFirst("privkey:".count))
            let bytes = stride(from: 0, to: hex.count, by: 2).compactMap {
                UInt8(String(hex[$0..<$0 + 2]), radix: 16)
            }
            let derived = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(bytes)).publicKey.rawRepresentation
            let expected = "nodekey:" + derived.map { String(format: "%02x", $0) }.joined()
            guard expected == keys.public_key.lowercased() else {
                throw TailcatError.invalidKey("public and private keys do not match")
            }
            self.json = json
            self.publicKey = publicKey
            self.privateKey = keys.private_key
            self.presharedKey = keys.preshared_key
        } catch {
            throw TailcatError.invalidKey("invalid C API key bundle")
        }
    }

    public static func generate() throws -> Identity {
        try Identity(json: CAPI.string { tc_key_generate($0, $1) })
    }

    public init(from decoder: any Decoder) throws {
        try self.init(json: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(json)
    }
}
