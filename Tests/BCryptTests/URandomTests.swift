@testable import BCrypt
import XCTest

final class URandomTests: XCTestCase {
    func testBytes() {
        // Arrange
        let count: UInt = 16

        // Act
        let bytes = try! URandom().bytes(count: count)

        // Assert
        XCTAssertEqual(bytes.count, Int(count))

        // Act/Assert
        XCTAssertThrowsError(try URandom(path: "/invalid/path").bytes(count: count)) { error in
            XCTAssertTrue(error is URandomError)
        }
    }

    func testErrors() {
        // Arrange
        let path = URandom.defaultPath
        let errno: Int32 = 1

        // Assert
        XCTAssertEqual(
            URandomError.open(path: path, errno: errno).localizedDescription,
            "[errno: \(errno)] Can't open a file at \"\(path)\"."
        )
        XCTAssertEqual(
            URandomError.read(path: path, errno: errno).localizedDescription,
            "[errno: \(errno)] Can't read a file at \"\(path)\"."
        )
    }
}
