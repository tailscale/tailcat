// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Dispatch

/// Runs blocking C calls off the Swift concurrency thread pool.
///
/// tailcat_server_start, tailcat_client_ping, tailcat_client_path_json,
/// tailcat_client_dial and tailcat_token_resolve block for the duration
/// of their network work, so they run on a dedicated dispatch queue and
/// callers await a continuation. They are never called on an actor
/// executor or on the cooperative pool.
enum Blocking {
    static let queue = DispatchQueue(
        label: "dev.tailcat.blocking",
        qos: .userInitiated,
        attributes: .concurrent
    )

    /// Runs body on the blocking queue and returns its result.
    static func run<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result(catching: body))
            }
        }
    }
}

extension Duration {
    /// The duration in whole milliseconds as the C layer takes timeouts,
    /// clamped to Int32. Zero means no limit beyond tailcat's own.
    var millisecondsForC: Int32 {
        let (seconds, attoseconds) = components
        if seconds < 0 {
            return 0
        }
        if seconds >= Int64(Int32.max) / 1000 {
            return Int32.max
        }
        return Int32(clamping: seconds * 1000 + attoseconds / 1_000_000_000_000_000)
    }
}
