// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// The errors TailcatKit throws.
public enum TailcatError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The underlying C handle is not valid, typically because the object
    /// was closed.
    case invalidHandle
    /// The connection token is malformed; the payload is the parser's
    /// message.
    case invalidToken(String)
    /// The identity JSON is malformed; the payload is the parser's message.
    case invalidKey(String)
    /// The identity leaves the relay to be picked when a server starts, so
    /// its token is only known once such a server is running.
    case relayNotFixed
    /// The operation needs a started server.
    case notStarted
    /// The server is already starting or started.
    case alreadyStarted
    /// The object (server, client, listener or connection) is closed.
    case closed
    /// The operation did not complete within its timeout.
    case timeout
    /// The port is not valid for the operation.
    case invalidPort
    /// A POSIX error: errno and its text.
    case posix(Int32, String)
    /// Any other error, with the text reported by the Go side.
    case internalError(String)

    /// A short description of the error.
    public var description: String {
        switch self {
        case .invalidHandle: "invalid handle"
        case .invalidToken(let message): "invalid connection token: \(message)"
        case .invalidKey(let message): "invalid identity: \(message)"
        case .relayNotFixed: "the identity's relay is chosen at start; the token is only known once a server using it has started"
        case .notStarted: "the server is not started"
        case .alreadyStarted: "the server is already started"
        case .closed: "closed"
        case .timeout: "timed out"
        case .invalidPort: "invalid port"
        case .posix(let code, let message): "\(message) (errno \(code))"
        case .internalError(let message): message
        }
    }
}

extension TailcatError {
    /// Throws the error a handle function's return code stands for, if any.
    static func check(_ rc: Int32, handle: Int32) throws {
        if rc != 0 {
            throw fromReturnCode(rc, handle: handle)
        }
    }

    /// Maps a handle function's non-zero return code: EBADF, ERANGE, or -1
    /// with the message tailcat_errmsg holds for the handle.
    static func fromReturnCode(_ rc: Int32, handle: Int32) -> TailcatError {
        switch rc {
        case EBADF:
            return .invalidHandle
        case ERANGE:
            return .internalError("buffer too small")
        default:
            return classify(message: lastMessage(handle: handle))
        }
    }

    /// Reads the last error message recorded on handle.
    static func lastMessage(handle: Int32) -> String {
        for size in [1024, 16384] {
            var buf = [CChar](repeating: 0, count: size)
            let rc = buf.withUnsafeMutableBufferPointer { tailcat_errmsg(handle, $0.baseAddress, $0.count) }
            switch rc {
            case 0:
                let message = CStrings.string(buf)
                return message.isEmpty ? "unknown error" : message
            case ERANGE:
                continue
            default:
                return "unknown error (handle \(handle) is invalid)"
            }
        }
        return "unknown error (message too long)"
    }

    /// Picks the error case that best fits a message from the Go side.
    static func classify(message: String) -> TailcatError {
        let m = message.lowercased()
        if m.contains("deadline exceeded") || m.contains("timeout") || m.contains("timed out") {
            return .timeout
        }
        if m.contains("already started") {
            return .alreadyStarted
        }
        if m.contains("server closed") || m.contains("client closed") {
            return .closed
        }
        if m.contains("connection refused") || m.contains("connection was refused") {
            return .posix(ECONNREFUSED, message)
        }
        return .internalError(message)
    }

    /// A POSIX error with the system's text for code.
    static func posix(_ code: Int32) -> TailcatError {
        .posix(code, String(cString: strerror(code)))
    }
}

/// Helpers for strings crossing the C boundary.
enum CStrings {
    /// Returns the text of a malloc'd C string and frees it; nil for NULL.
    static func take(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { free(p) }
        return String(cString: p)
    }

    /// Returns the bytes of a malloc'd C string and frees it; nil for NULL.
    static func takeData(_ p: UnsafeMutablePointer<CChar>?) -> Data? {
        guard let p else { return nil }
        defer { free(p) }
        return Data(bytes: p, count: strlen(p))
    }

    /// The string in a NUL-terminated buffer.
    static func string(_ buf: [CChar]) -> String {
        buf.withUnsafeBufferPointer { p in
            guard let base = p.baseAddress, p.contains(0) else { return "" }
            return String(cString: base)
        }
    }
}
