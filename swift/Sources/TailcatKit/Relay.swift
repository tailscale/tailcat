// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation

/// Relay configuration accepted by the upstream C API.
public enum RelaySelection: Sendable, Hashable {
    case automatic
    /// A positive DERP region ID from the relay map.
    case region(Int)
    /// A DERPRegion JSON object, using Go field names such as RegionID and Nodes.
    /// Useful for private relays. The C API validates its contents at creation.
    case custom(Data)
}

public struct ServerConfiguration: Sendable {
    public var identity: Identity?
    public var relay: RelaySelection
    public var derpMapURL: URL?
    /// An empty list allows any client possessing the secret server address.
    public var allowedClients: [NodePublicKey]

    public init(identity: Identity? = nil, relay: RelaySelection = .automatic,
                derpMapURL: URL? = nil, allowedClients: [NodePublicKey] = []) {
        self.identity = identity
        self.relay = relay
        self.derpMapURL = derpMapURL
        self.allowedClients = allowedClients
    }

    func json(identity: Identity) throws -> String {
        var config: [String: Any] = [
            "key": identity.privateKey,
            "preshared_key": identity.presharedKey,
            "allowed_clients": allowedClients.map(\.rawValue),
        ]
        if let derpMapURL { config["derp_map_url"] = derpMapURL.absoluteString }
        switch relay {
        case .automatic: break
        case .region(let id):
            guard id > 0, id <= Int(Int32.max) else {
                throw TailcatError.invalidArgument("DERP region ID must be positive and fit in Int32")
            }
            config["region_id"] = id
        case .custom(let json):
            guard let region = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
                throw TailcatError.invalidArgument("relay must be a DERPRegion JSON object")
            }
            config["region"] = region
        }
        return String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
    }
}
