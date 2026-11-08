// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A server using the upstream C API. Listening starts it automatically.
public actor TailcatServer {
    public nonisolated let publicKey: NodePublicKey
    public private(set) var address: TailcatAddress?
    private let handle: Handle
    private let logger: any LogSink

    public init(configuration: ServerConfiguration = .init(), logger: any LogSink = BlackholeLogger()) throws {
        let identity = try configuration.identity ?? Identity.generate()
        var raw: UInt64 = 0
        try configuration.json(identity: identity).withCInput { config in
            try CAPI.check { tc_server_new(config, &raw, $0) }
        }
        self.handle = Handle(raw)
        self.publicKey = identity.publicKey
        self.logger = logger
        logger.log("TailcatServer: created")
    }

    /// Starts the server and returns its secret address. Repeated starts succeed.
    /// nil disables the deadline while preserving Swift task cancellation.
    @discardableResult
    public func start(timeout: Duration? = .seconds(30)) async throws -> TailcatAddress {
        let raw = try handle.value()
        let address = try await Blocking.run(timeout: timeout) { token in
            try CAPI.check { tc_server_start(raw, token, $0) }
            let info = try CAPI.info(raw, token)
            guard let text = info.address, let address = TailcatAddress(rawValue: text) else {
                throw TailcatError.internalError("server info contained no address")
            }
            return address
        }
        _ = try handle.value() // close may have run while this actor was suspended.
        self.address = address
        logger.log("TailcatServer: started")
        return address
    }

    /// Starts the server if needed, then listens for TCP. Port 0 selects a free
    /// port, available as Listener.port. There is no catch-all listener.
    public func listen(on port: UInt16, timeout: Duration? = .seconds(30)) async throws -> Listener {
        let raw = try handle.value()
        let logger = logger
        return try await Blocking.run(timeout: timeout) { token in
            var listener: UInt64 = 0
            try CAPI.check { tc_server_listen(raw, token, port, Int32(TC_TCP), &listener, $0) }
            do {
                let info = try CAPI.info(listener, token)
                guard let port = info.localPort else {
                    throw TailcatError.internalError("listener info contained no port")
                }
                return Listener(handle: Handle(listener), port: port, logger: logger)
            } catch {
                _ = tc_close(listener, nil)
                throw error
            }
        }
    }

    /// Restricts future registrations to the allowlist. Existing flows remain.
    public func allow(_ key: NodePublicKey) async throws {
        let raw = try handle.value()
        try await Blocking.run { token in
            try key.rawValue.withCInput { key in
                try CAPI.check { tc_server_allow_client(raw, token, key, $0) }
            }
        }
    }

    /// Waits for TCP shutdown traffic before closing the peer. Use a finite limit.
    public func drain(timeout: Duration = .seconds(5)) async throws {
        let raw = try handle.value()
        try await Blocking.run(timeout: timeout) { token in
            try CAPI.check { tc_drain(raw, token, $0) }
        }
    }

    /// Closes the server, listeners, and accepted connections. Waits off-thread
    /// for their outstanding C calls to finish. Repeated closes are harmless.
    public func close() async {
        address = nil
        await handle.close()
        logger.log("TailcatServer: closed")
    }
}
