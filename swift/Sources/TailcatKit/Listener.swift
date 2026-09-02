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
        /// The source armed for the accept in progress, if any. While it
        /// is set, its cancel handler owns closing the descriptor.
        var source: SourceRef?
        /// The accept waiting for readability, if any.
        var waiter: CheckedContinuation<Void, any Error>?
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
                    return .success(ref)
                }
                switch armed {
                case .failure(let error):
                    continuation.resume(throwing: error)
                case .success(let ref):
                    ref.source.setEventHandler { [state, ref] in
                        let waiter = state.withLock { s -> CheckedContinuation<Void, any Error>? in
                            let w = s.waiter
                            s.waiter = nil
                            return w
                        }
                        ref.source.cancel()
                        waiter?.resume()
                    }
                    ref.source.setCancelHandler { [state, ref] in
                        // The source is unregistered now, so the
                        // descriptor may be closed if close() asked for it.
                        let (fdToClose, waiter) = state.withLock { s -> (Int32, CheckedContinuation<Void, any Error>?) in
                            var fdToClose: Int32 = -1
                            if let current = s.source, current.source === ref.source {
                                s.source = nil
                                if s.closed {
                                    fdToClose = s.fd
                                    s.fd = -1
                                }
                            }
                            let w = s.waiter
                            s.waiter = nil
                            return (fdToClose, w)
                        }
                        if fdToClose >= 0 {
                            _ = Darwin.close(fdToClose)
                        }
                        waiter?.resume(throwing: TailcatError.closed)
                    }
                    ref.source.activate()
                }
            }
        } onCancel: {
            let (ref, waiter) = state.withLock { s -> (SourceRef?, CheckedContinuation<Void, any Error>?) in
                let w = s.waiter
                s.waiter = nil
                return (s.source, w)
            }
            ref?.source.cancel()
            waiter?.resume(throwing: CancellationError())
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

    /// Closes the listener once: wakes a waiting accept with
    /// TailcatError.closed and closes the descriptor, directly or from the
    /// armed source's cancel handler.
    func close() {
        let (fdToClose, ref, waiter) = state.withLock { s -> (Int32, SourceRef?, CheckedContinuation<Void, any Error>?) in
            if s.closed {
                return (-1, nil, nil)
            }
            s.closed = true
            let w = s.waiter
            s.waiter = nil
            if let ref = s.source {
                return (-1, ref, w)
            }
            let fd = s.fd
            s.fd = -1
            return (fd, nil, w)
        }
        if let ref {
            ref.source.cancel()
        }
        if fdToClose >= 0 {
            _ = Darwin.close(fdToClose)
        }
        waiter?.resume(throwing: TailcatError.closed)
    }
}
