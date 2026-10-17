// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "BinaryCodable",
    platforms: [.macOS(.v10_13), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)],
    products: [
        .library(
            name: "LegacyBinaryCodable",
            targets: ["LegacyBinaryCodable"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "LegacyBinaryCodable",
            dependencies: []),
        .testTarget(
            name: "BinaryCodableTests",
            dependencies: ["LegacyBinaryCodable"]),
    ],
    swiftLanguageVersions: [.v5]
)
