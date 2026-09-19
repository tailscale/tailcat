// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
import os

/// Where TailcatKit and the Go side send their logs.
public protocol LogSink: Sendable {
    /// A descriptor the Go side writes its log lines to, or nil to discard
    /// them. It stays owned by the sink and must remain open for the life
    /// of the servers and clients using it.
    var logFileDescriptor: Int32? { get }

    /// Receives TailcatKit's own messages.
    func log(_ message: String)
}

/// Sends the Go side's logs to stderr and TailcatKit's to the unified
/// logging system (os.Logger, subsystem dev.tailcat.TailcatKit).
public struct DefaultLogger: LogSink {
    private static let logger = Logger(subsystem: "dev.tailcat.TailcatKit", category: "TailcatKit")

    /// Creates the logger.
    public init() {}

    /// Standard error, for the Go side's lines.
    public var logFileDescriptor: Int32? { STDERR_FILENO }

    /// Logs message at the info level.
    public func log(_ message: String) {
        Self.logger.info("\(message, privacy: .public)")
    }
}

/// Discards everything, on both sides (the Go side gets -1).
public struct BlackholeLogger: LogSink {
    /// Creates the logger.
    public init() {}

    /// Nil: the Go side discards its logs.
    public var logFileDescriptor: Int32? { nil }

    /// Discards message.
    public func log(_ message: String) {}
}
