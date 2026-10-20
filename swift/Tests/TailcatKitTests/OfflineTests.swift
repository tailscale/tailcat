// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import CTailcat
import Foundation
import Testing
@testable import TailcatKit

struct OfflineTests {
    @Test func ABIAndErrors() throws {
        #expect(tc_abi_version() == 1)
        let json = try CAPI.string { tc_build_info($0, $1) }
        #expect(try JSONSerialization.jsonObject(with: Data(json.utf8)) is [String: Any])
        // Status codes, not message content, decide the Swift error.
        #expect(CAPI.error(Int32(TC_TIMEOUT), "anything") as? TailcatError == .timeout)
        #expect(CAPI.error(Int32(TC_CLOSED), "timeout") as? TailcatError == .closed)
        #expect(CAPI.error(Int32(TC_FAILURE), "timeout") as? TailcatError == .internalError("timeout"))
        #expect(CAPI.error(Int32(TC_CANCELLED), nil) is CancellationError)
    }

    @Test func timeouts() {
        #expect(Duration.zero.nanosecondsForC == 0)
        #expect(Duration.seconds(-1).nanosecondsForC == 0)
        #expect(Duration.nanoseconds(1).nanosecondsForC == 1)
        #expect(Duration(secondsComponent: 0, attosecondsComponent: 1).nanosecondsForC == 1)
        #expect(Duration.milliseconds(1500).nanosecondsForC == 1_500_000_000)
        #expect(Duration.seconds(Int64.max).nanosecondsForC == Int64.max)
        #expect((Duration.seconds(9_223_372_036) + .nanoseconds(854_775_808)).nanosecondsForC == Int64.max)
    }

    @Test func preCancelledOperationDoesNotRun() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await Blocking.run { _ in
                Issue.record("cancelled task entered C operation")
                return 1
            }
        }
        do { _ = try await task.value; Issue.record("cancelled operation succeeded") }
        catch { #expect(error is CancellationError) }
    }

    @Test func serverBeforeStartAndAfterClose() async throws {
        let identity = try Identity.generate()
        let server = try TailcatServer(configuration: .init(identity: identity, relay: .region(302)))
        #expect(server.publicKey == identity.publicKey)
        #expect(await server.address == nil)
        try await server.allow(try Identity.generate().publicKey)
        try await server.drain()
        await server.close()
        await server.close()
        do { _ = try await server.start(); Issue.record("start after close succeeded") }
        catch { #expect(error as? TailcatError == .closed) }
    }

    @Test(arguments: [0, -1, Int(Int32.max) + 1])
    func rejectsInvalidRegion(_ id: Int) {
        #expect(throws: TailcatError.self) { try TailcatServer(configuration: .init(relay: .region(id))) }
    }

    @Test func rejectsInvalidCustomRegion() {
        #expect(throws: (any Error).self) {
            try TailcatServer(configuration: .init(relay: .custom(Data("[]".utf8))))
        }
    }

    @Test func pathMetadata() throws {
        let direct = try PathInfo(json: Data("{\"latency\":0.001,\"endpoint\":\"127.0.0.1:1234\",\"derp_region_code\":\"test\"}".utf8))
        #expect(direct.isDirect)
        #expect(direct.relayRegionCode == nil)
        #expect(direct.latency == .milliseconds(1))
        let relay = try PathInfo(json: Data("{\"latency\":0,\"endpoint\":\"\",\"derp_region_code\":\"test\"}".utf8))
        #expect(!relay.isDirect)
        #expect(relay.relayRegionCode == "test")
    }
}
