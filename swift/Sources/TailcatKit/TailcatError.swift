// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation

/// Errors returned by TailcatKit. C errors are classified by ABI status code.
public enum TailcatError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidArgument(String)
    case invalidAddress(String)
    case invalidKey(String)
    case closed
    case timeout
    case invalidPort
    case internalError(String)

    public var description: String {
        switch self {
        case .invalidArgument(let message): "invalid argument: \(message)"
        case .invalidAddress(let message): "invalid tailcat address: \(message)"
        case .invalidKey(let message): "invalid identity: \(message)"
        case .closed: "closed"
        case .timeout: "timed out"
        case .invalidPort: "invalid port"
        case .internalError(let message): message
        }
    }
}

/// A failed send that already handed bytes to the tunnel. Do not replay them.
public struct PartialWriteError: Error, Sendable {
    public let bytesWritten: Int
    public let underlyingError: any Error
}

/// The only owner of error and string allocations crossing the C boundary.
enum CAPI {
    static func error(_ status: Int32, _ message: String?) -> (any Error)? {
        switch Int(status) {
        case TC_OK: nil
        case TC_INVALID_ARGUMENT: TailcatError.invalidArgument(message ?? "invalid argument")
        case TC_CLOSED: TailcatError.closed
        case TC_TIMEOUT: TailcatError.timeout
        case TC_CANCELLED: CancellationError()
        default: TailcatError.internalError(message ?? "C API status \(status)")
        }
    }

    static func check(_ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32) throws {
        var message: UnsafeMutablePointer<CChar>?
        let status = body(&message)
        if let error = error(status, take(message)) { throw error }
    }

    static func string(_ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
                                UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32) throws -> String {
        var out: UnsafeMutablePointer<CChar>?
        defer { tc_free(out) }
        try check { body(&out, $0) }
        guard let out else { throw TailcatError.internalError("C API returned no string") }
        return String(cString: out)
    }

    static func take(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else { return nil }
        defer { tc_free(pointer) }
        return String(cString: pointer)
    }

    static func info(_ handle: UInt64, _ token: UInt64) throws -> ResourceInfo {
        let json = try string { tc_info(handle, token, $0, $1) }
        return try JSONDecoder().decode(ResourceInfo.self, from: Data(json.utf8))
    }
}

struct ResourceInfo: Decodable, Sendable {
    var address: String?
    var publicKey: String?
    var localAddress: String?
    var remoteAddress: String?

    enum CodingKeys: String, CodingKey {
        case address
        case publicKey = "public_key"
        case localAddress = "local_address"
        case remoteAddress = "remote_address"
    }

    var localPort: UInt16? {
        localAddress?.split(separator: ":").last.flatMap { UInt16($0) }
    }
}

extension String {
    // The C ABI borrows input strings and never modifies or retains them.
    func withCInput<T>(_ body: (UnsafeMutablePointer<CChar>) throws -> T) rethrows -> T {
        try withCString { try body(UnsafeMutablePointer(mutating: $0)) }
    }
}
