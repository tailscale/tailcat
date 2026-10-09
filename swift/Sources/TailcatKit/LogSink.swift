// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import os

/// Receives Swift wrapper lifecycle messages. The C API discards Go logs.
public protocol LogSink: Sendable {
    func log(_ message: String)
}

public struct DefaultLogger: LogSink {
    private static let logger = Logger(subsystem: "dev.tailcat.TailcatKit", category: "TailcatKit")
    public init() {}
    public func log(_ message: String) { Self.logger.info("\(message, privacy: .public)") }
}

public struct BlackholeLogger: LogSink {
    public init() {}
    public func log(_ message: String) {}
}
