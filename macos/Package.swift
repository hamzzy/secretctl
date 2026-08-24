// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "secretctl-macos",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SecretctlKit", targets: ["SecretctlKit"]),
        .executable(name: "secretctl-menubar", targets: ["SecretctlMenuBar"]),
        .executable(name: "secretctl-doctor", targets: ["SecretctlDoctor"]),
    ],
    targets: [
        // Transport, crypto and UI-safe models. Deliberately free of AppKit so
        // the security-critical layer can be unit tested without a bundle.
        .target(
            name: "SecretctlKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "SecretctlMenuBar",
            dependencies: ["SecretctlKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // Console diagnostic. The menu-bar app has nowhere to print, so this
        // runs the identical client and reports each step of the connection.
        .executableTarget(
            name: "SecretctlDoctor",
            dependencies: ["SecretctlKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "SecretctlKitTests",
            dependencies: ["SecretctlKit"],
            resources: [.copy("Vectors")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
