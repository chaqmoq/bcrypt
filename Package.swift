// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "chaqmoq-bcrypt",
    products: [
        .library(name: "BCrypt", targets: ["BCrypt"])
    ],
    targets: [
        .target(name: "BCryptC"),
        .target(name: "BCrypt", dependencies: [
            .target(name: "BCryptC")
        ]),
        .testTarget(name: "BCryptTests", dependencies: [
            .target(name: "BCrypt")
        ])
    ],
    swiftLanguageVersions: [.v5]
)
