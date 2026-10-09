// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

public actor TailcatClient {
    public nonisolated let address: TailcatAddress
    private let handle: Handle
    private let logger: any LogSink

    /// Creates a client without network access. The first ping/dial starts it.
    public init(address: TailcatAddress, identity: Identity? = nil, derpMapURL: URL? = nil,
                logger: any LogSink = BlackholeLogger()) throws {
        _ = try address.parse()
        var config = ["address": address.rawValue]
        if let identity { config["key"] = identity.privateKey }
        if let derpMapURL { config["derp_map_url"] = derpMapURL.absoluteString }
        let json = String(decoding: try JSONEncoder().encode(config), as: UTF8.self)
        var raw: UInt64 = 0
        try json.withCInput { input in
            try CAPI.check { tc_client_new(input, &raw, $0) }
        }
        self.handle = Handle(raw)
        self.address = address
        self.logger = logger
        logger.log("TailcatClient: created")
    }

    public var publicKey: NodePublicKey {
        get async throws {
            let raw = try handle.value()
            return try await Blocking.run { token in
                let info = try CAPI.info(raw, token)
                guard let text = info.publicKey, let key = NodePublicKey(rawValue: text) else {
                    throw TailcatError.internalError("client info contained no public key")
                }
                return key
            }
        }
    }

    /// Measures relay round-trip latency. Zero is valid (sub-millisecond RTT).
    public func ping(timeout: Duration? = .seconds(10)) async throws -> Duration {
        let raw = try handle.value()
        return try await Blocking.run(timeout: timeout) { token in
            var latency: Int32 = 0
            try CAPI.check { tc_client_ping(raw, token, &latency, $0) }
            return .milliseconds(latency)
        }
    }

    public func path(timeout: Duration? = .seconds(10)) async throws -> PathInfo {
        let raw = try handle.value()
        return try await Blocking.run(timeout: timeout) { token in
            let json = try CAPI.string { tc_client_disco_ping(raw, token, $0, $1) }
            return try PathInfo(json: Data(json.utf8))
        }
    }

    public func connect(port: UInt16, timeout: Duration? = .seconds(15)) async throws -> Connection {
        guard port != 0 else { throw TailcatError.invalidPort }
        let raw = try handle.value()
        return try await Blocking.run(timeout: timeout) { token in
            var connection: UInt64 = 0
            try CAPI.check { tc_client_dial(raw, token, port, Int32(TC_TCP), &connection, $0) }
            return try Connection.adopt(connection, token: token)
        }
    }

    public func drain(timeout: Duration = .seconds(5)) async throws {
        let raw = try handle.value()
        try await Blocking.run(timeout: timeout) { token in
            try CAPI.check { tc_drain(raw, token, $0) }
        }
    }

    /// Closes the client and its connections and waits for pending C calls.
    public func close() async {
        await handle.close()
        logger.log("TailcatClient: closed")
    }
}

public struct PathInfo: Sendable, Hashable {
    public let isDirect: Bool
    public let endpoint: String?
    public let relayRegionCode: String?
    public let latency: Duration
    public let json: Data

    init(json: Data) throws {
        struct Result: Decodable {
            var latency: Double
            var endpoint: String
            var derp_region_code: String
        }
        let raw = try JSONDecoder().decode(Result.self, from: json)
        endpoint = raw.endpoint.isEmpty ? nil : raw.endpoint
        isDirect = endpoint != nil
        relayRegionCode = isDirect || raw.derp_region_code.isEmpty ? nil : raw.derp_region_code
        latency = .seconds(raw.latency)
        self.json = json
    }
}
