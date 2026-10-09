// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Dispatch
import os

/// Keeps synchronous C calls, including resource teardown, off actor executors.
enum Blocking {
    static let queue = DispatchQueue(label: "dev.tailcat.blocking", qos: .userInitiated, attributes: .concurrent)

    static func perform<T: Sendable>(on queue: DispatchQueue = queue,
                                    _ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result(catching: body)) }
        }
    }

    /// Each operation gets its own token. Its deadline includes dispatch queue
    /// time, and Swift cancellation interrupts C without retiring the resource.
    /// A successful result wins a cancellation race and remains caller-owned.
    static func run<T: Sendable>(timeout: Duration? = nil, on queue: DispatchQueue = queue,
                                _ body: @escaping @Sendable (UInt64) throws -> T) async throws -> T {
        try Task.checkCancellation()
        let token = try CancellationToken(timeout: timeout)
        return try await withTaskCancellationHandler {
            try await perform(on: queue) { try body(token.handle) }
        } onCancel: {
            token.cancel()
        }
    }
}

private final class CancellationToken: Sendable {
    let handle: UInt64

    init(timeout: Duration?) throws {
        var handle: UInt64 = 0
        try CAPI.check { tc_token_new(timeout?.nanosecondsForC ?? -1, &handle, $0) }
        self.handle = handle
    }

    func cancel() { _ = tc_token_cancel(handle, nil) }
    // The operation and its cancellation handler retain us until both return.
    deinit { _ = tc_close(handle, nil) }
}

/// Owns one never-reused C handle. Explicit close waits for teardown on a worker;
/// deinit schedules it there without blocking an actor or the cooperative pool.
final class Handle: Sendable {
    private struct State: Sendable {
        var raw: UInt64
        var closing: Task<Void, Never>?
    }
    private let state: OSAllocatedUnfairLock<State>

    init(_ handle: UInt64) { state = OSAllocatedUnfairLock(initialState: State(raw: handle)) }

    func value() throws -> UInt64 {
        try state.withLock {
            guard $0.raw != 0 else { throw TailcatError.closed }
            return $0.raw
        }
    }

    func close() async {
        let closing = state.withLock { state in
            if let closing = state.closing { return closing }
            let raw = state.raw
            state.raw = 0
            let closing = Task.detached {
                _ = try? await Blocking.perform { tc_close(raw, nil) }
            }
            state.closing = closing
            return closing
        }
        await closing.value
    }

    deinit {
        let raw = state.withLock { $0.raw }
        if raw != 0 { Blocking.queue.async { _ = tc_close(raw, nil) } }
    }
}

extension Duration {
    /// ABI timeouts are nanoseconds. Round positive fractions up and saturate.
    /// Zero/negative durations expire immediately; nil means no deadline.
    var nanosecondsForC: Int64 {
        guard self > .zero else { return 0 }
        let (seconds, attoseconds) = components
        let (whole, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return .max }
        let fraction = attoseconds / 1_000_000_000 + (attoseconds % 1_000_000_000 > 0 ? 1 : 0)
        let (result, sumOverflow) = whole.addingReportingOverflow(fraction)
        return sumOverflow ? .max : result
    }
}
