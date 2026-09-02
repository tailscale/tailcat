// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Dispatch
import Foundation
import os

/// A TCP connection through the tunnel: one accepted by a Listener or one
/// opened by TailcatClient.connect.
///
/// The connection is one end of a socketpair pumped by the Go side. It is
/// driven by DispatchIO, so reads and writes never block a Swift
/// concurrency thread. Reads deliver whatever has arrived (up to
/// maxLength) as soon as anything has; the Go side applies TCP
/// backpressure once the socket buffer and one read's worth of internal
/// buffering are full. One receive (or incoming stream consumer) at a
/// time; sends may overlap with receives.
public final class Connection: Sendable {
    /// The peer's address as "ip:port"; nil for connections opened by
    /// TailcatClient.connect.
    public let remoteAddress: String?
    /// The server port the peer dialed; nil for connections opened by
    /// TailcatClient.connect.
    public let localPort: UInt16?

    private let fd: Int32
    private let queue: DispatchQueue
    private let io: DispatchIO
    private let state: OSAllocatedUnfairLock<State>

    private struct State: Sendable {
        var closed = false
        var writeClosed = false
        /// Bytes read but not yet handed to a receiver.
        var buffer = Data()
        var eof = false
        var readError: TailcatError?
        /// Whether a DispatchIO read is outstanding, and its bookkeeping:
        /// an operation that ends without error before delivering what it
        /// asked for hit EOF.
        var reading = false
        var readRequested = 0
        var readDelivered = 0
        /// The receive waiting for data, if any.
        var receiver: CheckedContinuation<Data, any Error>?
        var receiverMax = 0
    }

    /// Wraps the descriptor, which the connection now owns and closes
    /// exactly once.
    init(fd: Int32, remoteAddress: String?, localPort: UInt16?) {
        self.fd = fd
        self.remoteAddress = remoteAddress
        self.localPort = localPort
        self.state = OSAllocatedUnfairLock(initialState: State())
        let queue = DispatchQueue(label: "dev.tailcat.connection")
        self.queue = queue
        self.io = DispatchIO(type: .stream, fileDescriptor: fd, queue: queue) { _ in
            // Runs once the channel is closed and every operation on it
            // has finished: the one moment the descriptor is no longer in
            // use, and the only place it is closed.
            _ = Darwin.close(fd)
        }
        // Deliver reads as soon as any byte is available rather than
        // waiting for a full chunk.
        io.setLimit(lowWater: 1)
    }

    deinit {
        close()
    }

    /// Sends data, returning once it has been handed to the tunnel (the
    /// Go side forwards it as the peer accepts it). Throws
    /// TailcatError.closed when the connection is closed, or
    /// TailcatError.posix for a write error such as EPIPE after the peer
    /// went away. Task cancellation does not interrupt a send in
    /// progress.
    public func send(_ data: Data) async throws {
        try state.withLock { s in
            if s.closed {
                throw TailcatError.closed
            }
        }
        if data.isEmpty {
            return
        }
        let chunk = data.withUnsafeBytes { DispatchData(bytes: $0) }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            io.write(offset: 0, data: chunk, queue: queue) { [weak self] done, _, error in
                guard done else { return }
                if error == 0 {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: self?.ioError(error) ?? TailcatError.closed)
                }
            }
        }
    }

    /// Receives up to maxLength bytes, returning as soon as any are
    /// available. Returns empty Data at EOF (the peer closed or
    /// half-closed its side). Throws TailcatError.closed once the
    /// connection is closed, and CancellationError if the task is
    /// cancelled while waiting; data arriving meanwhile is kept for the
    /// next receive.
    public func receive(maxLength: Int = 65_536) async throws -> Data {
        guard maxLength > 0 else {
            throw TailcatError.internalError("receive needs a positive maxLength")
        }
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                enum Action {
                    case resume(Data)
                    case fail(TailcatError)
                    case wait(startRead: Bool)
                }
                let action: Action = state.withLock { s in
                    if s.closed {
                        return .fail(.closed)
                    }
                    if !s.buffer.isEmpty {
                        return .resume(Self.take(&s, maxLength))
                    }
                    if let error = s.readError {
                        return .fail(error)
                    }
                    if s.eof {
                        return .resume(Data())
                    }
                    if s.receiver != nil {
                        return .fail(.internalError("a receive is already in progress"))
                    }
                    s.receiver = continuation
                    s.receiverMax = maxLength
                    if s.reading {
                        return .wait(startRead: false)
                    }
                    s.reading = true
                    s.readRequested = maxLength
                    s.readDelivered = 0
                    return .wait(startRead: true)
                }
                switch action {
                case .resume(let data):
                    continuation.resume(returning: data)
                case .fail(let error):
                    continuation.resume(throwing: error)
                case .wait(let startRead):
                    if startRead {
                        self.startRead(length: maxLength)
                    }
                }
            }
        } onCancel: {
            let receiver = state.withLock { s -> CheckedContinuation<Data, any Error>? in
                let r = s.receiver
                s.receiver = nil
                return r
            }
            receiver?.resume(throwing: CancellationError())
        }
    }

    /// The bytes the peer sends, as they arrive, until EOF. Pull-based:
    /// each step is one receive(), so it applies backpressure and stops
    /// when the consuming task is cancelled. Single consumer.
    public var incoming: AsyncThrowingStream<Data, any Error> {
        AsyncThrowingStream(unfolding: { [self] in
            let chunk = try await self.receive()
            return chunk.isEmpty ? nil : chunk
        })
    }

    /// Half-closes the connection for writing (shutdown(2) with SHUT_WR):
    /// the peer's reads see EOF once it has read everything sent, while
    /// its writes still arrive here. Idempotent.
    public func closeWrite() {
        state.withLock { s in
            guard !s.closed, !s.writeClosed else { return }
            s.writeClosed = true
            // Under the lock so the descriptor cannot be closed meanwhile.
            _ = Darwin.shutdown(fd, SHUT_WR)
        }
    }

    /// Closes the connection: outstanding operations end with
    /// TailcatError.closed, the Go side tears the tunnel connection down,
    /// and the descriptor is closed once DispatchIO is done with it.
    /// Idempotent; deinit calls it.
    public func close() {
        let (first, receiver) = state.withLock { s -> (Bool, CheckedContinuation<Data, any Error>?) in
            if s.closed {
                return (false, nil)
            }
            s.closed = true
            let r = s.receiver
            s.receiver = nil
            return (true, r)
        }
        guard first else { return }
        io.close(flags: .stop)
        receiver?.resume(throwing: TailcatError.closed)
    }

    private func startRead(length: Int) {
        io.read(offset: 0, length: length, queue: queue) { [weak self] done, data, error in
            self?.handleRead(done: done, data: data, error: error)
        }
    }

    private func handleRead(done: Bool, data: DispatchData?, error: Int32) {
        typealias Resume = (CheckedContinuation<Data, any Error>, Result<Data, TailcatError>)
        let (resume, restart): (Resume?, Int?) = state.withLock { s in
            if let data, !data.isEmpty {
                for region in data.regions {
                    region.withUnsafeBytes { s.buffer.append(contentsOf: $0) }
                }
                s.readDelivered += data.count
            }
            if done {
                s.reading = false
                if error != 0 {
                    s.readError = error == ECANCELED || s.closed ? .closed : TailcatError.posix(error)
                } else if s.readDelivered < s.readRequested {
                    s.eof = true
                }
            }
            guard let receiver = s.receiver else {
                return (nil, nil)
            }
            if !s.buffer.isEmpty {
                s.receiver = nil
                return ((receiver, .success(Self.take(&s, s.receiverMax))), nil)
            }
            if let readError = s.readError {
                s.receiver = nil
                return ((receiver, .failure(readError)), nil)
            }
            if s.eof {
                s.receiver = nil
                return ((receiver, .success(Data())), nil)
            }
            if !s.reading && !s.closed {
                // The operation ended without anything for the waiting
                // receiver (it completed its length in an earlier
                // delivery); read again on its behalf.
                s.reading = true
                s.readRequested = s.receiverMax
                s.readDelivered = 0
                return (nil, s.receiverMax)
            }
            return (nil, nil)
        }
        if let restart {
            startRead(length: restart)
        }
        if let (receiver, result) = resume {
            receiver.resume(with: result.mapError { $0 as any Error })
        }
    }

    /// Removes and returns up to max bytes from the buffer.
    private static func take(_ s: inout State, _ max: Int) -> Data {
        let n = Swift.min(max, s.buffer.count)
        let out = Data(s.buffer.prefix(n))
        s.buffer.removeFirst(n)
        return out
    }

    /// Maps a DispatchIO error code.
    private func ioError(_ error: Int32) -> TailcatError {
        if error == ECANCELED {
            return .closed
        }
        let closed = state.withLock { $0.closed }
        return closed ? .closed : TailcatError.posix(error)
    }
}
