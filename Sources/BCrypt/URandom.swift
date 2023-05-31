import Foundation
#if os(Linux) || os(FreeBSD)
import Glibc
#else
import Darwin
#endif

final class URandom {
    let path: String
    private let file: UnsafeMutablePointer<FILE>

    init(path: String = "/dev/urandom") throws {
        self.path = path
        guard let file = fopen(path, "rb") else { throw URandomError.open(path: path, errno: errno) }
        self.file = file
    }

    deinit {
        fclose(file)
    }

    func bytes(count: Int) throws -> [UInt8] {
        var bytes = [Int8](repeating: 0, count: count)
        guard fread(&bytes, 1, count, file) == count else { throw URandomError.read(path: path, errno: errno) }

        return bytes.map { UInt8(bitPattern: $0) }
    }
}

enum URandomError: LocalizedError {
    case open(path: String, errno: Int32)
    case read(path: String, errno: Int32)

    var errorDescription: String? {
        switch self {
        case .open(let path, let errno): return "[\(errno)] Can't open a file at \"\(path)\"."
        case .read(let path, let errno): return "[\(errno)] Can't read a file at \"\(path)\"."
        }
    }
}
