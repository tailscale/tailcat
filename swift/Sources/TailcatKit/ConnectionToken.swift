// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A node's public key in tailcat's text form, "nodekey:" followed by 64
/// hex digits. Servers allow clients by this key.
public struct NodePublicKey: Sendable, Hashable, Codable, RawRepresentable, CustomStringConvertible {
    /// The text form, "nodekey:<hex>".
    public let rawValue: String

    /// Creates a key from its text form, or returns nil unless it is
    /// "nodekey:" followed by exactly 64 hex digits.
    public init?(rawValue: String) {
        guard rawValue.hasPrefix("nodekey:") else { return nil }
        let hex = rawValue.dropFirst("nodekey:".count)
        guard hex.count == 64, hex.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { return nil }
        self.rawValue = rawValue
    }

    /// The text form.
    public var description: String { rawValue }

    /// Decodes the text form, validating it.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        guard let key = NodePublicKey(rawValue: raw) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "not a nodekey:<hex> string"))
        }
        self = key
    }

    /// Encodes the text form.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// A server's connection token (the "tc..." string a tailcat server
/// announces), which names the server's keys and its relay.
public struct ConnectionToken: Sendable, Hashable, Codable, RawRepresentable, CustomStringConvertible {
    /// The token text.
    public let rawValue: String

    /// Creates a token from its text. Only the "tc" prefix is checked
    /// here; parse() validates the rest.
    public init?(rawValue: String) {
        guard rawValue.hasPrefix("tc"), rawValue.count > 2 else { return nil }
        self.rawValue = rawValue
    }

    /// The token text.
    public var description: String { rawValue }

    /// Decodes the token text, checking its prefix.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        guard let token = ConnectionToken(rawValue: raw) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "not a tc... token"))
        }
        self = token
    }

    /// Encodes the token text.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// Decodes the token without touching the network (tailcat_token_parse,
    /// the same as "tailcat parse"). Throws TailcatError.invalidToken for a
    /// malformed token.
    public func parse() throws -> TokenInfo {
        var out: UnsafeMutablePointer<CChar>? = nil
        let err = rawValue.withCString { tailcat_token_parse($0, &out) }
        if let message = CStrings.take(err) {
            free(out)
            throw TailcatError.invalidToken(message)
        }
        guard let json = CStrings.takeData(out) else {
            throw TailcatError.internalError("tailcat_token_parse returned no JSON")
        }
        return try TokenInfo(json: json)
    }

    /// Returns the self-contained form of the token, with the relay's
    /// details embedded so clients need no DERP map fetch (the same as
    /// "tailcat resolve"). A token that already embeds them comes back
    /// unchanged. The DERP map is fetched from derpMapURL, or the default
    /// map when nil. The work runs off the Swift concurrency threads. The
    /// timeout is rounded up to whole milliseconds; zero means no limit
    /// beyond the fetch's own. Throws TailcatError.invalidToken for a
    /// malformed token, TailcatError.timeout when time runs out, and
    /// otherwise the fetch's error, such as
    /// TailcatError.posix(ECONNREFUSED, _) or TailcatError.internalError.
    public func resolved(derpMapURL: URL? = nil, timeout: Duration = .seconds(10)) async throws -> ConnectionToken {
        let token = rawValue
        let url = derpMapURL?.absoluteString
        let ms = timeout.millisecondsForC
        let resolved: String = try await Blocking.run {
            var out: UnsafeMutablePointer<CChar>? = nil
            let err = token.withCString { t -> UnsafeMutablePointer<CChar>? in
                if let url {
                    return url.withCString { tailcat_token_resolve(t, $0, ms, &out) }
                }
                return tailcat_token_resolve(t, nil, ms, &out)
            }
            if let message = CStrings.take(err) {
                free(out)
                // Resolving fails either because the token is malformed,
                // which parse() detects offline, or because the DERP map
                // could not be fetched, which says nothing about the
                // token.
                if (try? self.parse()) == nil {
                    throw TailcatError.invalidToken(message)
                }
                throw TailcatError.classify(message: message)
            }
            guard let text = CStrings.take(out) else {
                throw TailcatError.internalError("tailcat_token_resolve returned no token")
            }
            return text
        }
        guard let result = ConnectionToken(rawValue: resolved) else {
            throw TailcatError.internalError("tailcat_token_resolve returned an unexpected token")
        }
        return result
    }
}

/// The contents of a connection token.
public struct TokenInfo: Sendable, Hashable {
    /// The server's node public key.
    public let serverPublicKey: NodePublicKey
    /// The DERP map region the server uses, when the token references one
    /// by ID; nil when it embeds the relay details instead.
    public let regionID: Int?
    /// The hostnames of the relays embedded in the token, in order; empty
    /// when the token references a region by ID.
    public let relayHosts: [String]
    /// The full decoded token as JSON, the output of "tailcat parse".
    public let json: Data

    /// Decodes the JSON of tailcat_token_parse.
    init(json: Data) throws {
        let raw: RawToken
        do {
            raw = try JSONDecoder().decode(RawToken.self, from: json)
        } catch {
            throw TailcatError.internalError("decoding token JSON: \(error)")
        }
        guard let key = NodePublicKey(rawValue: raw.serverPublic) else {
            throw TailcatError.invalidToken("unexpected server public key \(raw.serverPublic)")
        }
        serverPublicKey = key
        let hosts = (raw.region ?? []).flatMap { $0.nodes ?? [] }.compactMap { $0.hostName }.filter { !$0.isEmpty }
        relayHosts = hosts
        if let id = raw.regionID, id > 0, hosts.isEmpty {
            regionID = id
        } else {
            regionID = nil
        }
        self.json = json
    }

    private struct RawToken: Decodable {
        var serverPublic: String
        var regionID: Int?
        var region: [RawRegion]?

        enum CodingKeys: String, CodingKey {
            case serverPublic = "ServerPublic"
            case regionID = "RegionID"
            case region = "Region"
        }
    }

    private struct RawRegion: Decodable {
        var nodes: [RawNode]?

        enum CodingKeys: String, CodingKey {
            case nodes = "Nodes"
        }
    }

    private struct RawNode: Decodable {
        var hostName: String?

        enum CodingKeys: String, CodingKey {
            case hostName = "HostName"
        }
    }
}
