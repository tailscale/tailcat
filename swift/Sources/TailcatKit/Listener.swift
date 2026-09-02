// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Dispatch
import Foundation
import os

/// A port registered on a TailcatServer, from which accepted connections
/// are taken. Closing it (or the server) unregisters the port.
public actor Listener {
    /// The registered port; 0 is the catch-all listener, which receives
    /// connections to every port that has no listener of its own.
    public nonisolated let port: UInt16

    private let core: ListenerCore
    private let logger: any LogSink

    /// Wraps a tailcat_listener descriptor, which the listener now owns.
    init(port: UInt16, fd: Int32, logger: any LogSink) {
        self.port = port
        self.core = ListenerCore(fd: fd)
        self.logger = logger
    }

    deinit {
        core.close()
    }

    /// Waits for the next connection. It awaits the listener descriptor's
    /// readability with a DispatchSource, then dequeues the connection
    /// (tailcat_accept and tailcat_conn_info). Throws TailcatError.closed
    /// once the listener or its server is closed, and CancellationError if
    /// the task is cancelled while waiting. One accept at a time.
    public func accept() async throws -> Connection {
        try await core.waitReadable()
        let connection = try core.accept()
        logger.log("Listener: accepted \(connection.remoteAddress ?? "?") on port \(connection.localPort ?? port)")
        return connection
    }

    /// The connections as they arrive, until the listener is closed.
    /// Each step is one accept(), so it stops when the consuming task is
    /// cancelled. Single consumer.
    public nonisolated var connections: AsyncThrowingStream<Connection, any Error> {
        AsyncThrowingStream(unfolding: { [self] in
            do {
                return try await self.accept()
            } catch TailcatError.closed {
                return nil
            }
        })
    }

    /// Stops listening: a waiting accept() throws TailcatError.closed and
    /// the descriptor is closed, which unregisters the port on the Go
    /// side. Idempotent; deinit calls it. Connections already accepted
    /// are unaffected.
    public func close() {
        core.close()
    }
}

/// The lock-protected state behind a Listener, shared with the dispatch
/// handlers that watch the descriptor.
final class ListenerCore: Sendable {
    /// A read source, as a Sendable value for the state.
    private struct SourceRef: @unchecked Sendable {
        let source: any DispatchSourceRead
    }

    private struct State: Sendable {
        var fd: Int32
        var closed = false
        /// The source armed for the accept in progress, if any. Its cancel
        /// handler is the one place the source is retired and the waiter
        /// resumed, so a following accept never finds a source that is
        /// still winding down; while it is set, that handler also owns
        /// closing the descriptor.
        var source: SourceRef?
        /// The accept waiting for readability, set and cleared together
        /// with source.
        var waiter: CheckedContinuation<Void, any Error>?
        /// What happened to the armed source: the descriptor became
        /// readable, or the waiting task was cancelled.
        var readable = false
        var taskCancelled = false
    }

    /// What one waitReadable call has armed, for its cancellation handler,
    /// which must act on that arm alone, and whether the task was
    /// cancelled before the arm was recorded.
    private struct Registration: Sendable {
        var ref: SourceRef?
        var cancelled = false
    }

    /// Why an armed source was retired.
    private enum Outcome {
        case readable, cancelled, closed
    }

    private let state: OSAllocatedUnfairLock<State>
    private static let queue = DispatchQueue(label: "dev.tailcat.listener")

    init(fd: Int32) {
        state = OSAllocatedUnfairLock(initialState: State(fd: fd))
    }

    /// Suspends until the descriptor is readable, that is, until
    /// tailcat_accept will not block.
    func waitReadable() async throws {
        try Task.checkCancellation()
        let registration = OSAllocatedUnfairLock(initialState: Registration())
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let armed: Result<SourceRef, TailcatError> = state.withLock { s in
                    if s.closed || s.fd < 0 {
                        return .failure(.closed)
                    }
                    if s.source != nil || s.waiter != nil {
                        return .failure(.internalError("an accept is already in progress"))
                    }
                    let ref = SourceRef(source: DispatchSource.makeReadSource(fileDescriptor: s.fd, queue: Self.queue))
                    s.source = ref
                    s.waiter = continuation
                    s.readable = false
                    s.taskCancelled = false
                    return .success(ref)
                }
                switch armed {
                case .failure(let error):
                    continuation.resume(throwing: error)
                case .success(let ref):
                    ref.source.setEventHandler { [state, ref] in
                        // Note the readability and retire the source; its
                        // cancel handler resumes the waiter.
                        state.withLock { s in
                            if let current = s.source, current.source === ref.source {
                                s.readable = true
                            }
                        }
                        ref.source.cancel()
                    }
                    ref.source.setCancelHandler { [state, ref] in
                        // The source is unregistered now: retire it, close
                        // the descriptor if close() asked for that, and
                        // resume the waiter with what happened.
                        let (fdToClose, waiter, outcome) = state.withLock { s -> (Int32, CheckedContinuation<Void, any Error>?, Outcome) in
                            guard let current = s.source, current.source === ref.source else {
                                return (-1, nil, .closed)
                            }
                            s.source = nil
                            let w = s.waiter
                            s.waiter = nil
                            var fdToClose: Int32 = -1
                            if s.closed {
                                fdToClose = s.fd
                                s.fd = -1
                            }
                            let outcome: Outcome
                            if s.taskCancelled {
                                outcome = .cancelled
                            } else if s.closed || !s.readable {
                                outcome = .closed
                            } else {
                                outcome = .readable
                            }
                            return (fdToClose, w, outcome)
                        }
                        if fdToClose >= 0 {
                            _ = Darwin.close(fdToClose)
                        }
                        switch outcome {
                        case .readable:
                            waiter?.resume()
                        case .cancelled:
                            waiter?.resume(throwing: CancellationError())
                        case .closed:
                            waiter?.resume(throwing: TailcatError.closed)
                        }
                    }
                    ref.source.activate()
                    // Record the arm for the cancellation handler. If the
                    // task was cancelled before now, that handler found
                    // nothing to act on, so act here.
                    let cancelledMeanwhile = registration.withLock { r -> Bool in
                        r.ref = ref
                        return r.cancelled
                    }
                    if cancelledMeanwhile {
                        cancelWait(ref)
                    }
                }
            }
        } onCancel: {
            let ref = registration.withLock { r -> SourceRef? in
                r.cancelled = true
                return r.ref
            }
            if let ref {
                cancelWait(ref)
            }
        }
    }

    /// Ends the wait armed with ref, if it is still the current one, with
    /// CancellationError: the source's cancel handler resumes the waiter.
    private func cancelWait(_ ref: SourceRef) {
        let current = state.withLock { s -> Bool in
            guard let current = s.source, current.source === ref.source else {
                return false
            }
            s.taskCancelled = true
            return true
        }
        if current {
            ref.source.cancel()
        }
    }

    /// Dequeues one connection. Call after waitReadable, so the read does
    /// not block; the descriptor stays open meanwhile because only close()
    /// closes it, and it runs on the same actor.
    func accept() throws -> Connection {
        let fd = try state.withLock { s -> Int32 in
            guard !s.closed, s.fd >= 0 else {
                throw TailcatError.closed
            }
            return s.fd
        }
        // Dispatch may have put the descriptor in non-blocking mode;
        // tailcat_accept expects a blocking read (the data is there).
        let flags = fcntl(fd, F_GETFL)
        if flags >= 0, flags & O_NONBLOCK != 0 {
            _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
        }
        var connFd: Int32 = -1
        let rc = tailcat_accept(fd, &connFd)
        guard rc == 0, connFd >= 0 else {
            // The Go side closed the listener (the server closed) or no
            // longer knows it; either way it is finished.
            close()
            throw TailcatError.closed
        }
        var buf = [CChar](repeating: 0, count: 128)
        var localPort: Int32 = 0
        let irc = buf.withUnsafeMutableBufferPointer { p in
            tailcat_conn_info(fd, connFd, p.baseAddress, p.count, &localPort)
        }
        let known = irc == 0 && localPort >= 0 && localPort <= 65535
        return Connection(
            fd: connFd,
            remoteAddress: known ? CStrings.string(buf) : nil,
            localPort: known ? UInt16(localPort) : nil
        )
    }

    /// Closes the listener once: a waiting accept ends with
    /// TailcatError.closed, and the descriptor is closed, directly or from
    /// the armed source's cancel handler once the source has let go of
    /// it.
    func close() {
        let (fdToClose, ref) = state.withLock { s -> (Int32, SourceRef?) in
            if s.closed {
                return (-1, nil)
            }
            s.closed = true
            if let ref = s.source {
                return (-1, ref)
            }
            let fd = s.fd
            s.fd = -1
            return (fd, nil)
        }
        if let ref {
            ref.source.cancel()
        }
        if fdToClose >= 0 {
            _ = Darwin.close(fdToClose)
        }
    }
}
