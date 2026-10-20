// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Dispatch
import Foundation
import os

/// Keeps synchronous C operations off actor executors.
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

/// A single teardown thread independent of the Dispatch worker pool. Idle C
/// reads/accepts can occupy every Dispatch worker, so queuing close there would
/// prevent the very operation that interrupts those calls from ever running.
private final class Teardown: Sendable {
    static let shared = Teardown()
    private let pending = OSAllocatedUnfairLock(initialState: [@Sendable () -> Void]())
    private let ready = DispatchSemaphore(value: 0)

    private init() {
        let pending = pending
        let ready = ready
        let thread = Thread {
            while true {
                ready.wait()
                let jobs = pending.withLock { pending in
                    let jobs = pending
                    pending.removeAll(keepingCapacity: true)
                    return jobs
                }
                for job in jobs { job() }
            }
        }
        thread.name = "dev.tailcat.teardown"
        thread.start()
    }

    func submit(_ body: @escaping @Sendable () -> Void) {
        pending.withLock { $0.append(body) }
        ready.signal()
    }

    func close(_ raw: UInt64) async {
        await withCheckedContinuation { continuation in
            submit {
                _ = tc_close(raw, nil)
                continuation.resume()
            }
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

/// Owns one never-reused C handle. Explicit close and deinit both use the
/// teardown thread without blocking an actor or the cooperative pool.
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
                await Teardown.shared.close(raw)
            }
            state.closing = closing
            return closing
        }
        await closing.value
    }

    deinit {
        let raw = state.withLock { $0.raw }
        if raw != 0 { Teardown.shared.submit { _ = tc_close(raw, nil) } }
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
