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

/// A server's tailcat address (the "tc..." string a tailcat server
/// announces), which names the server's keys and its relay.
public struct TailcatAddress: Sendable, Hashable, Codable, RawRepresentable, CustomStringConvertible {
    /// The address text.
    public let rawValue: String

    /// Creates an address from its text. Only the "tc" prefix is checked
    /// here; parse() validates the rest.
    public init?(rawValue: String) {
        guard rawValue.hasPrefix("tc"), rawValue.count > 2, !rawValue.utf8.contains(0) else { return nil }
        self.rawValue = rawValue
    }

    /// The address text.
    public var description: String { rawValue }

    /// Decodes the address text, checking its prefix.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        guard let address = TailcatAddress(rawValue: raw) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "not a tc... address"))
        }
        self = address
    }

    /// Encodes the address text.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// Parses public metadata locally. The JSON omits the pre-shared key.
    public func parse() throws -> AddressInfo {
        do {
            let json = try rawValue.withCInput { input in
                try CAPI.string { tc_address_parse(input, $0, $1) }
            }
            return try AddressInfo(json: Data(json.utf8))
        } catch TailcatError.invalidArgument(let message) {
            throw TailcatError.invalidAddress(message)
        }
    }

    /// Embeds relay details, fetching the relay map if needed. Swift task
    /// cancellation interrupts the lookup without freeing its buffers early.
    public func resolved(derpMapURL: URL? = nil, timeout: Duration? = .seconds(10)) async throws -> TailcatAddress {
        _ = try parse()
        return try await Blocking.run(timeout: timeout) { token in
            let text = try rawValue.withCInput { address in
                try (derpMapURL?.absoluteString ?? "").withCInput { url in
                    try CAPI.string { tc_address_resolve(token, address, url, $0, $1) }
                }
            }
            guard let result = TailcatAddress(rawValue: text) else {
                throw TailcatError.internalError("C API returned an invalid address")
            }
            return result
        }
    }
}

/// The contents of a tailcat address.
public struct AddressInfo: Sendable, Hashable {
    /// The server's node public key.
    public let serverPublicKey: NodePublicKey
    /// The DERP map region the server uses, when the address references one
    /// by ID; nil when it embeds the relay details instead.
    public let regionID: Int?
    /// The hostnames of the relays embedded in the address, in order; empty
    /// when the address references a region by ID.
    public let relayHosts: [String]
    /// The full decoded address as JSON, public metadata from the C API.
    public let json: Data

    /// Decodes the JSON of tc_address_parse.
    init(json: Data) throws {
        let raw: RawAddress
        do {
            raw = try JSONDecoder().decode(RawAddress.self, from: json)
        } catch {
            throw TailcatError.internalError("decoding address JSON: \(error)")
        }
        guard let key = NodePublicKey(rawValue: raw.serverPublic) else {
            throw TailcatError.invalidAddress("unexpected server public key \(raw.serverPublic)")
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

    private struct RawAddress: Decodable {
        var serverPublic: String
        var regionID: Int?
        var region: [RawRegion]?

        enum CodingKeys: String, CodingKey {
            case serverPublic = "public_key"
            case regionID = "region_id"
            case region = "regions"
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
