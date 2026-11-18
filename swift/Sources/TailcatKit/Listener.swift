// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// A TCP listener. Accepted connections belong to the server and survive close.
public actor Listener {
    public nonisolated let port: UInt16
    private let handle: Handle
    private let logger: any LogSink

    init(handle: Handle, port: UInt16, logger: any LogSink) {
        self.handle = handle
        self.port = port
        self.logger = logger
    }

    /// Cancellation interrupts just this accept; the listener remains usable.
    public func accept(timeout: Duration? = nil) async throws -> Connection {
        let raw = try handle.value()
        return try await Blocking.run(timeout: timeout) { token in
            var connection: UInt64 = 0
            try CAPI.check { tc_listener_accept(raw, token, &connection, $0) }
            return try Connection.adopt(connection, token: token)
        }
    }

    public nonisolated var connections: AsyncThrowingStream<Connection, any Error> {
        AsyncThrowingStream(unfolding: { [self] in
            do { return try await accept() }
            catch TailcatError.closed { return nil }
        })
    }

    public func close() async {
        await handle.close()
        logger.log("Listener: closed")
    }
}
