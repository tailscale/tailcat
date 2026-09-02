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
    /// rounded up, since a positive timeout must never become 0, which
    /// means no limit, and clamped to Int32. Zero or less means no limit
    /// beyond tailcat's own.
    var millisecondsForC: Int32 {
        guard self > .zero else {
            return 0
        }
        let (seconds, attoseconds) = components
        if seconds >= Int64(Int32.max) / 1000 {
            return Int32.max
        }
        let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000
        let (wholeMilliseconds, rest) = attoseconds.quotientAndRemainder(dividingBy: attosecondsPerMillisecond)
        let milliseconds = seconds * 1000 + wholeMilliseconds + (rest > 0 ? 1 : 0)
        return Int32(clamping: milliseconds)
    }
}
