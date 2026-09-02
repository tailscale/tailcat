// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A tailcat identity: the private key JSON as written by "tailcat genkey"
/// (a tailcat.PrivateKey, with the relay choice recorded in its Public
/// part). It is a private key: store it in the Keychain, not in
/// preferences or logs. Codable as the JSON string itself.
public struct Identity: Sendable, Codable, Hashable {
    /// The key file JSON.
    public let json: String

    private let cachedPublicKey: NodePublicKey

    /// Adopts an existing key JSON, validating it (tailcat_key_public).
    /// Throws TailcatError.invalidKey when it does not parse.
    public init(json: String) throws {
        var out: UnsafeMutablePointer<CChar>? = nil
        let err = json.withCString { tailcat_key_public($0, &out) }
        if let message = CStrings.take(err) {
            free(out)
            throw TailcatError.invalidKey(message)
        }
        guard let text = CStrings.take(out), let key = NodePublicKey(rawValue: text) else {
            throw TailcatError.invalidKey("unexpected public key format")
        }
        self.json = json
        self.cachedPublicKey = key
    }

    /// Generates a new identity (tailcat_key_generate) whose relay is
    /// picked automatically when a server starts with it, the same as
    /// "tailcat genkey".
    public static func generate() throws -> Identity {
        var out: UnsafeMutablePointer<CChar>? = nil
        if let message = CStrings.take(tailcat_key_generate(&out)) {
            free(out)
            throw TailcatError.internalError(message)
        }
        guard let json = CStrings.take(out) else {
            throw TailcatError.internalError("tailcat_key_generate returned no key")
        }
        return try Identity(json: json)
    }

    /// The identity's node public key, "nodekey:<hex>". Computed once, at
    /// init.
    public var publicKey: NodePublicKey { cachedPublicKey }

    /// The token a server using this identity will announce
    /// (tailcat_key_token). It is only known ahead of time when the key
    /// names a fixed DERP region or embeds relay hosts; with automatic
    /// selection it throws TailcatError.relayNotFixed, and the token must
    /// be read from a started TailcatServer instead.
    public func token() throws -> ConnectionToken {
        var out: UnsafeMutablePointer<CChar>? = nil
        let err = json.withCString { tailcat_key_token($0, &out) }
        if let message = CStrings.take(err) {
            free(out)
            if message.lowercased().contains("region") {
                throw TailcatError.relayNotFixed
            }
            throw TailcatError.invalidKey(message)
        }
        guard let text = CStrings.take(out), let token = ConnectionToken(rawValue: text) else {
            throw TailcatError.internalError("tailcat_key_token returned an unexpected token")
        }
        return token
    }

    /// Decodes the key JSON (as a single string), validating it.
    public init(from decoder: any Decoder) throws {
        let json = try decoder.singleValueContainer().decode(String.self)
        try self.init(json: json)
    }

    /// Encodes the key JSON as a single string.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(json)
    }

    /// Identities are equal when their JSON is.
    public static func == (lhs: Identity, rhs: Identity) -> Bool {
        lhs.json == rhs.json
    }

    /// Hashes the JSON.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(json)
    }
}
