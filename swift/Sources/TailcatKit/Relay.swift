// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import Foundation

/// Which DERP relay a server bootstraps through (and clients rendezvous
/// at).
public enum RelaySelection: Sendable, Hashable {
    /// The relay recorded in the server's identity if it has one,
    /// otherwise the nearest region of the DERP map, measured at start.
    case automatic
    /// A DERP map region by ID (tailcat_server_set_region_id). It
    /// overrides the identity's choice; 0 means the nearest region,
    /// ignoring the identity.
    case region(Int)
    /// Your own DERP relays, by hostname (tailcat_server_set_relay_hosts).
    /// The server connects to the first; the address always embeds them.
    case hosts([String])
}

/// What a TailcatServer is built from.
public struct ServerConfiguration: Sendable {
    /// The server's identity; nil generates an ephemeral one whose address
    /// nobody has seen before.
    public var identity: Identity? = nil
    /// The relay to use.
    public var relay: RelaySelection = .automatic
    /// The DERP map to resolve regions against; nil uses tailcat's default
    /// map (https://tailcat.dev/derpmap.json).
    public var derpMapURL: URL? = nil
    /// Whether the address embeds the relay's details (self-contained but
    /// longer, like "tailcat serve --full-address") instead of a region
    /// ID. Relay hosts are always embedded.
    public var embedRelayInAddress: Bool = false
    /// Clients allowed to connect, by public key. Empty allows everyone;
    /// once any key is listed (or allowed later), only listed keys can
    /// connect.
    public var allowedClients: [NodePublicKey] = []

    /// The defaults: an ephemeral identity, automatic relay selection, the
    /// default DERP map, a short address, every client allowed.
    public init() {}

    /// A configuration with the given settings; unspecified ones keep
    /// their defaults.
    public init(
        identity: Identity? = nil,
        relay: RelaySelection = .automatic,
        derpMapURL: URL? = nil,
        embedRelayInAddress: Bool = false,
        allowedClients: [NodePublicKey] = []
    ) {
        self.identity = identity
        self.relay = relay
        self.derpMapURL = derpMapURL
        self.embedRelayInAddress = embedRelayInAddress
        self.allowedClients = allowedClients
    }
}
