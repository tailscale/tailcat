// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A tailcat server: it announces a tailcat address, and clients holding
/// the address dial TCP ports on it, which Listeners accept.
///
/// Create it, register listeners, then start() (which does the network
/// work off the Swift concurrency threads) and share the address. Ports may
/// also be registered after start.
public actor TailcatServer {
    /// The server's node public key, "nodekey:<hex>", known before start.
    public nonisolated let publicKey: NodePublicKey

    /// The tailcat address, once start() has returned it.
    public private(set) var address: TailcatAddress?

    private var handle: Int32
    private var state: State = .idle
    private let logger: any LogSink

    private enum State {
        case idle, starting, running, closed
    }

    /// Creates a server (tailcat_server_new and the tailcat_server_set_*
    /// calls). Nothing touches the network until start().
    public init(configuration: ServerConfiguration = .init(), logger: any LogSink = BlackholeLogger()) throws {
        let h = tailcat_server_new()
        guard h != 0 else {
            throw TailcatError.internalError("tailcat_server_new returned no handle")
        }
        let key: NodePublicKey
        do {
            try TailcatError.check(tailcat_set_logfd(h, logger.logFileDescriptor ?? -1), handle: h)
            if let identity = configuration.identity {
                try TailcatError.check(identity.json.withCString { tailcat_server_set_key(h, $0) }, handle: h)
            }
            switch configuration.relay {
            case .automatic:
                break
            case .region(let id):
                guard id >= 0, id <= Int(Int32.max) else {
                    throw TailcatError.internalError("invalid DERP region ID \(id)")
                }
                try TailcatError.check(tailcat_server_set_region_id(h, Int32(id)), handle: h)
            case .hosts(let hosts):
                let list = hosts.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                guard !list.isEmpty else {
                    throw TailcatError.internalError("the relay host list is empty")
                }
                try TailcatError.check(list.joined(separator: ",").withCString { tailcat_server_set_relay_hosts(h, $0) }, handle: h)
            }
            if let url = configuration.derpMapURL {
                try TailcatError.check(url.absoluteString.withCString { tailcat_server_set_derpmap_url(h, $0) }, handle: h)
            }
            if configuration.embedRelayInAddress {
                try TailcatError.check(tailcat_server_set_embed_relay(h, 1), handle: h)
            }
            for client in configuration.allowedClients {
                try TailcatError.check(client.rawValue.withCString { tailcat_server_allow_client(h, $0) }, handle: h)
            }
            var buf = [CChar](repeating: 0, count: 128)
            try TailcatError.check(buf.withUnsafeMutableBufferPointer { tailcat_server_public_key(h, $0.baseAddress, $0.count) }, handle: h)
            guard let parsed = NodePublicKey(rawValue: CStrings.string(buf)) else {
                throw TailcatError.internalError("unexpected server public key format")
            }
            key = parsed
        } catch {
            _ = tailcat_server_close(h)
            throw error
        }
        self.publicKey = key
        self.handle = h
        self.logger = logger
        logger.log("TailcatServer: created, public key \(key)")
    }

    deinit {
        if handle != 0 {
            _ = tailcat_server_close(handle)
        }
    }

    /// Registers port (1 to 65535) for incoming connections and returns
    /// its Listener; 0 registers the catch-all listener, which receives
    /// connections to every port without one. Works before and after
    /// start. A port may be registered once until its listener is closed.
    public func listen(on port: UInt16) throws -> Listener {
        let h = try activeHandle()
        var fd: Int32 = -1
        try TailcatError.check(tailcat_server_listen(h, Int32(port), &fd), handle: h)
        guard fd >= 0 else {
            throw TailcatError.internalError("tailcat_server_listen returned no listener")
        }
        logger.log("TailcatServer: listening on port \(port)")
        return Listener(port: port, fd: fd, logger: logger)
    }

    /// Starts the server (tailcat_server_start, off-thread): resolves the
    /// relay, fetching the DERP map and measuring latencies as needed, and
    /// returns the tailcat address, also kept in `address`. Throws
    /// TailcatError.alreadyStarted on a second call. Like the tailcat CLI
    /// it returns once the server is configured; the relay connection
    /// completes in the background right after, so a client pinging
    /// within the first seconds may time out and should retry.
    public func start() async throws -> TailcatAddress {
        switch state {
        case .closed:
            throw TailcatError.closed
        case .starting, .running:
            throw TailcatError.alreadyStarted
        case .idle:
            break
        }
        let h = handle
        state = .starting
        logger.log("TailcatServer: starting")
        do {
            try await Blocking.run {
                try TailcatError.check(tailcat_server_start(h), handle: h)
            }
        } catch {
            if state == .closed {
                throw TailcatError.closed
            }
            // A failed start may be retried.
            state = .idle
            throw error
        }
        guard state == .starting else {
            throw TailcatError.closed
        }
        var buf = [CChar](repeating: 0, count: 4096)
        try TailcatError.check(buf.withUnsafeMutableBufferPointer { tailcat_server_addr(h, $0.baseAddress, $0.count) }, handle: h)
        guard let address = TailcatAddress(rawValue: CStrings.string(buf)) else {
            throw TailcatError.internalError("unexpected address format")
        }
        self.address = address
        state = .running
        logger.log("TailcatServer: started, address \(address)")
        return address
    }

    /// Allows a client by public key, before or after start. The allow
    /// list gates registration: until any key is allowed every client may
    /// register; once one is, only allowed clients can. A client that
    /// registered while the list was empty stays registered, its pings
    /// keep succeeding and it can still open connections until the server
    /// closes or the client restarts; to lock a server down from the
    /// start, list its clients in ServerConfiguration.allowedClients.
    public func allow(_ key: NodePublicKey) throws {
        let h = try activeHandle()
        try TailcatError.check(key.rawValue.withCString { tailcat_server_allow_client(h, $0) }, handle: h)
    }

    /// The server's WireGuard and relay status, the JSON encoding of
    /// ipnstate.Status. Throws TailcatError.notStarted before start.
    public func status() async throws -> Data {
        switch state {
        case .closed:
            throw TailcatError.closed
        case .idle, .starting:
            throw TailcatError.notStarted
        case .running:
            break
        }
        let h = handle
        return try await Blocking.run {
            var out: UnsafeMutablePointer<CChar>? = nil
            try TailcatError.check(tailcat_server_status_json(h, &out), handle: h)
            guard let json = CStrings.takeData(out) else {
                throw TailcatError.internalError("tailcat_server_status_json returned no JSON")
            }
            return json
        }
    }

    /// Shuts the server down: listeners and accepted connections are
    /// closed on the Go side (their reads see EOF, their Listener and
    /// Connection objects still own their descriptors until closed), the
    /// relay connection is torn down and the handle is freed. Idempotent;
    /// deinit calls it.
    public func close() {
        guard handle != 0 else { return }
        let h = handle
        handle = 0
        state = .closed
        _ = tailcat_server_close(h)
        logger.log("TailcatServer: closed")
    }

    private func activeHandle() throws -> Int32 {
        guard handle != 0, state != .closed else {
            throw TailcatError.closed
        }
        return handle
    }
}
