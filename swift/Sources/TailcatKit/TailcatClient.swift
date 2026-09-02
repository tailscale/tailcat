// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A tailcat client: given a server's connection token, it pings the
/// server and dials TCP ports on it.
///
/// Nothing happens on the network until the first ping, path or connect,
/// which brings the tunnel up (resolving the relay, connecting to it and
/// registering with the server). Those calls run off the Swift
/// concurrency threads.
public actor TailcatClient {
    /// The server's connection token.
    public nonisolated let token: ConnectionToken

    private var handle: Int32
    private let logger: any LogSink

    /// Creates a client for the server named by token (tailcat_client_new),
    /// with an optional identity (so the server can allow it by public
    /// key; ephemeral otherwise) and DERP map URL (used when the token
    /// references a region by ID). Throws TailcatError.invalidToken for a
    /// malformed token.
    public init(token: ConnectionToken, identity: Identity? = nil, derpMapURL: URL? = nil, logger: any LogSink = BlackholeLogger()) throws {
        let h = token.rawValue.withCString { tailcat_client_new($0) }
        guard h != 0 else {
            var message = "malformed token"
            do {
                _ = try token.parse()
            } catch TailcatError.invalidToken(let text) {
                message = text
            } catch {}
            throw TailcatError.invalidToken(message)
        }
        do {
            try TailcatError.check(tailcat_set_logfd(h, logger.logFileDescriptor ?? -1), handle: h)
            if let identity {
                try TailcatError.check(identity.json.withCString { tailcat_client_set_key(h, $0) }, handle: h)
            }
            if let derpMapURL {
                try TailcatError.check(derpMapURL.absoluteString.withCString { tailcat_client_set_derpmap_url(h, $0) }, handle: h)
            }
        } catch {
            _ = tailcat_client_close(h)
            throw error
        }
        self.token = token
        self.handle = h
        self.logger = logger
    }

    deinit {
        if handle != 0 {
            _ = tailcat_client_close(handle)
        }
    }

    /// The client's node public key, "nodekey:<hex>", generating the
    /// ephemeral key if no identity was given. Give it to the server's
    /// allow(_:).
    public var publicKey: NodePublicKey {
        get throws {
            let h = try activeHandle()
            var buf = [CChar](repeating: 0, count: 128)
            try TailcatError.check(buf.withUnsafeMutableBufferPointer { tailcat_client_public_key(h, $0.baseAddress, $0.count) }, handle: h)
            guard let key = NodePublicKey(rawValue: CStrings.string(buf)) else {
                throw TailcatError.internalError("unexpected client public key format")
            }
            return key
        }
    }

    /// Checks that the server is reachable and accepts this client, and
    /// returns the relay round trip (tailcat_client_ping, off-thread).
    /// Each call sends one probe: a server that does not allow this
    /// client, or one still connecting to its relay right after starting,
    /// shows up as TailcatError.timeout, which is worth a retry. A zero
    /// timeout means no limit beyond tailcat's own.
    public func ping(timeout: Duration = .seconds(10)) async throws -> Duration {
        let h = try activeHandle()
        let ms = timeout.millisecondsForC
        let latencyMs: Double = try await Blocking.run {
            var latency = 0.0
            try TailcatError.check(tailcat_client_ping(h, ms, &latency), handle: h)
            return latency
        }
        return .milliseconds(latencyMs)
    }

    /// Reports how packets reach the server (tailcat_client_path_json,
    /// off-thread): a direct path, or the relay carrying them. Calling it
    /// repeatedly nudges direct path discovery along. A zero timeout means
    /// no limit beyond tailcat's own.
    public func path(timeout: Duration = .seconds(10)) async throws -> PathInfo {
        let h = try activeHandle()
        let ms = timeout.millisecondsForC
        let json: Data = try await Blocking.run {
            var out: UnsafeMutablePointer<CChar>? = nil
            try TailcatError.check(tailcat_client_path_json(h, ms, &out), handle: h)
            guard let json = CStrings.takeData(out) else {
                throw TailcatError.internalError("tailcat_client_path_json returned no JSON")
            }
            return json
        }
        return try PathInfo(json: json)
    }

    /// Opens a TCP connection to port on the server (tailcat_client_dial,
    /// off-thread). Throws TailcatError.invalidPort for port 0 and
    /// TailcatError.posix(ECONNREFUSED, _) when nothing listens on the
    /// port. A zero timeout means no limit beyond tailcat's own.
    public func connect(port: UInt16, timeout: Duration = .seconds(15)) async throws -> Connection {
        guard port != 0 else {
            throw TailcatError.invalidPort
        }
        let h = try activeHandle()
        let ms = timeout.millisecondsForC
        let fd: Int32 = try await Blocking.run {
            var fd: Int32 = -1
            try TailcatError.check(tailcat_client_dial(h, Int32(port), ms, &fd), handle: h)
            guard fd >= 0 else {
                throw TailcatError.internalError("tailcat_client_dial returned no connection")
            }
            return fd
        }
        logger.log("TailcatClient: connected to port \(port)")
        return Connection(fd: fd, remoteAddress: nil, localPort: nil)
    }

    /// Shuts the client down: connections opened through it are closed
    /// on the Go side (their reads see EOF; the Connection objects still
    /// own their descriptors until closed), the tunnel is torn down and
    /// the handle is freed. Idempotent; deinit calls it.
    public func close() {
        guard handle != 0 else { return }
        let h = handle
        handle = 0
        _ = tailcat_client_close(h)
        logger.log("TailcatClient: closed")
    }

    private func activeHandle() throws -> Int32 {
        guard handle != 0 else {
            throw TailcatError.closed
        }
        return handle
    }
}

/// How a client's packets reach the server, from TailcatClient.path.
public struct PathInfo: Sendable, Hashable {
    /// Whether the probe came back over a direct (peer-to-peer) path.
    public let isDirect: Bool
    /// The direct path's "ip:port", when isDirect.
    public let endpoint: String?
    /// The code of the DERP region relaying the packets, when not direct.
    public let relayRegionCode: String?
    /// The probe's round trip.
    public let latency: Duration
    /// The full result, the JSON encoding of ipnstate.PingResult.
    public let json: Data

    /// Decodes the JSON of tailcat_client_path_json.
    init(json: Data) throws {
        let raw: RawResult
        do {
            raw = try JSONDecoder().decode(RawResult.self, from: json)
        } catch {
            throw TailcatError.internalError("decoding path JSON: \(error)")
        }
        if let err = raw.err, !err.isEmpty {
            throw TailcatError.internalError(err)
        }
        let endpoint = (raw.endpoint ?? "").isEmpty ? nil : raw.endpoint
        self.isDirect = endpoint != nil
        self.endpoint = endpoint
        let code = (raw.derpRegionCode ?? "").isEmpty ? nil : raw.derpRegionCode
        self.relayRegionCode = endpoint == nil ? code : nil
        self.latency = .seconds(raw.latencySeconds ?? 0)
        self.json = json
    }

    private struct RawResult: Decodable {
        var err: String?
        var latencySeconds: Double?
        var endpoint: String?
        var derpRegionCode: String?

        enum CodingKeys: String, CodingKey {
            case err = "Err"
            case latencySeconds = "LatencySeconds"
            case endpoint = "Endpoint"
            case derpRegionCode = "DERPRegionCode"
        }
    }
}
