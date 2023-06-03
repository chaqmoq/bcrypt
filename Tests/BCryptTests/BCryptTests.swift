@testable import BCrypt
import XCTest

final class BCryptTests: XCTestCase {
    func testAlgorithms() {
        // Assert
        XCTAssertEqual(BCrypt.Algorithm.checksumCount, 31)
        XCTAssertEqual(BCrypt.Algorithm.revisionCount, 4)
        XCTAssertEqual(BCrypt.Algorithm.revisionCostSaltCount, 29)
        XCTAssertEqual(BCrypt.Algorithm.maxCost, 31)
        XCTAssertEqual(BCrypt.Algorithm.minCost, 4)
        XCTAssertEqual(BCrypt.Algorithm.saltCount, 22)
        XCTAssertEqual(BCrypt.Algorithm.allCases.count, 3)
        XCTAssertEqual(BCrypt.Algorithm._2a.rawValue, "$2a$")
        XCTAssertEqual(BCrypt.Algorithm._2b.rawValue, "$2b$")
        XCTAssertEqual(BCrypt.Algorithm._2y.rawValue, "$2y$")
    }

    func testErrors() {
        // Arrange
        let invalidCost: UInt = 3
        let invalidHash = "invalidHash"
        let invalidPlaintext = "invalidPlaintext"
        let invalidSalt = "invalidSalt"

        // Assert
        XCTAssertEqual(
            BCryptError.invalidCost(invalidCost).localizedDescription,
            "The cost \"\(invalidCost)\" must be between \(BCrypt.Algorithm.minCost) and \(BCrypt.Algorithm.maxCost)."
        )
        XCTAssertEqual(
            BCryptError.invalidHash(invalidHash).localizedDescription,
            "The hash \"\(invalidHash)\" is not a valid BCrypt hash."
        )
        XCTAssertEqual(
            BCryptError.invalidPlaintext(invalidPlaintext).localizedDescription,
            "Can't hash \"\(invalidPlaintext)\"."
        )
        XCTAssertEqual(
            BCryptError.invalidSalt(invalidSalt).localizedDescription,
            "The salt \"\(invalidSalt)\" is not a valid BCrypt salt."
        )
    }

    func testGenerateRandomBase64EncodedString() {
        // Arrange
        let bcrypt = BCrypt()
        let count: UInt = 16
        let length = Int(ceil(Double(count) * 1.37))

        // Act
        let base64EncodedString = try! bcrypt.generateRandomBase64EncodedString(count: count)

        // Assert
        XCTAssertEqual(base64EncodedString.count, length)
    }

    func testGenerateSalt() {
        // Arrange
        let bcrypt = BCrypt()
        let costs: [UInt] = [9, 10]
        let invalidCosts: [UInt] = [BCrypt.Algorithm.minCost - 1, BCrypt.Algorithm.maxCost + 1]

        for cost in costs {
            for algorithm in BCrypt.Algorithm.allCases {
                // Arrange
                let prefix = algorithm.rawValue + (cost < 10 ? "0\(cost)" : "\(cost)") + "$"

                // Act
                let salt = try! bcrypt.generateSalt(cost: cost, algorithm: algorithm)

                // Assert
                XCTAssertTrue(salt.starts(with: prefix))
            }
        }

        for invalidCost in invalidCosts {
            for algorithm in BCrypt.Algorithm.allCases {
                // Act/Assert
                XCTAssertThrowsError(try bcrypt.generateSalt(cost: invalidCost, algorithm: algorithm)) { error in
                    XCTAssertTrue(error is BCryptError)
                }
            }
        }
    }

    func testVerify() {
        // Arrange
        let bcrypt = BCrypt()
        let costs: [UInt] = [9, 10]
        let plaintexts = [
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "~`!@#$%^&*()_+-{};:\"/\\?.,"
        ]
        let invalidHash = "invalidHash"
        let invalidSalt = "invalidSalt"

        for cost in costs {
            // Arrange
            let salt = try! bcrypt.generateSalt(cost: cost)

            for plaintext in plaintexts {
                // Act/Assert
                XCTAssertTrue(try! bcrypt.verify(plaintext, against: bcrypt.hash(plaintext)))
                XCTAssertThrowsError(try bcrypt.verify(plaintext, against: invalidHash)) { error in
                    XCTAssertTrue(error is BCryptError)
                }
                XCTAssertTrue(try! bcrypt.verify(plaintext, against: bcrypt.hash(plaintext, salt: salt)))
                XCTAssertThrowsError(try bcrypt.verify(plaintext, against: bcrypt.hash(plaintext, salt: invalidSalt))) { error in
                    XCTAssertTrue(error is BCryptError)
                }
            }
        }
    }
}
