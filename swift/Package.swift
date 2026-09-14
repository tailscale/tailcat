// swift-tools-version: 6.0
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import PackageDescription

let package = Package(
    name: "TailcatKit",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "TailcatKit", targets: ["TailcatKit"]),
        .executable(name: "tailcat-demo", targets: ["tailcat-demo"]),
    ],
    targets: [
        // The Go library as a static archive per platform, built by
        // `make xcframework` in ../libtailcat.
        .binaryTarget(name: "CTailcat", path: "CTailcat.xcframework"),
        .target(
            name: "TailcatKit",
            dependencies: ["CTailcat"],
            linkerSettings: [
                // The Go runtime and its net package need these on Darwin.
                .linkedFramework("CoreFoundation"),
                .linkedFramework("Security"),
                .linkedLibrary("resolv"),
            ]
        ),
        .executableTarget(
            name: "tailcat-demo",
            dependencies: ["TailcatKit"],
            path: "Sources/TailcatDemo"
        ),
        .testTarget(name: "TailcatKitTests", dependencies: ["TailcatKit"]),
    ],
    swiftLanguageModes: [.v6]
)
