import BCryptC
import Foundation

public struct BCrypt {
    public init() {}

    public func generateRandomBase64EncodedString(count: UInt) throws -> String {
        let randomBytes = try URandom().bytes(count: count)
        let capacity = Int(ceil(Double(count) * 1.37))
        let encodedBytes = UnsafeMutablePointer<Int8>.allocate(capacity: capacity)
        defer { encodedBytes.deallocate() }
        encode_base64(encodedBytes, randomBytes, randomBytes.count)

        return String(cString: encodedBytes)
    }

    public func generateSalt(cost: UInt, algorithm: Algorithm = ._2b) throws -> String {
        try assertCost(cost)
        let encodedSalt = try generateRandomBase64EncodedString(count: 16)

        return algorithm.rawValue + (cost < 10 ? "0\(cost)" : "\(cost)") + "$" + encodedSalt
    }

    public func hash(_ plaintext: String, cost: UInt = 12, algorithm: Algorithm = ._2b) throws -> String {
        try hash(plaintext, salt: try generateSalt(cost: cost, algorithm: algorithm))
    }

    public func hash(_ plaintext: String, salt: String) throws -> String {
        try assertSalt(salt)
        let algorithm: Algorithm

        if salt.count == Algorithm.saltCount {
            algorithm = ._2b
        } else {
            let revision = String(salt.prefix(Algorithm.revisionCount))

            if let detectedAlgorithm = Algorithm(rawValue: revision) {
                algorithm = detectedAlgorithm
            } else {
                throw BCryptError.invalidSalt(salt)
            }
        }

        let salt = algorithm == Algorithm._2y
        ? Algorithm._2b.rawValue + salt.dropFirst(Algorithm.revisionCount)
        : salt

        let capacity = 128
        let hashedBytes = UnsafeMutablePointer<Int8>.allocate(capacity: capacity)
        defer { hashedBytes.deallocate() }
        let hash = bcrypt_hashpass(plaintext, salt, hashedBytes, capacity)
        guard hash == 0 else { throw BCryptError.invalidPlaintext(plaintext) }

        return algorithm.rawValue + String(cString: hashedBytes).dropFirst(Algorithm.revisionCount)
    }

    public func verify(_ plaintext: String, against hashedText: String) throws -> Bool {
        let revision = String(hashedText.prefix(Algorithm.revisionCount))
        guard Algorithm(rawValue: revision) != nil else { throw BCryptError.invalidHash(hashedText) }
        let salt = String(hashedText.prefix(Algorithm.revisionCostSaltCount))
        guard !salt.isEmpty, salt.count == Algorithm.revisionCostSaltCount else {
            throw BCryptError.invalidHash(hashedText)
        }
        let checksum = String(hashedText.suffix(Algorithm.checksumCount))
        guard !checksum.isEmpty, checksum.count == Algorithm.checksumCount else {
            throw BCryptError.invalidHash(hashedText)
        }
        let hash = try hash(plaintext, salt: salt)
        let hashChecksum = String(hash.suffix(Algorithm.checksumCount))

        return !hashChecksum.isEmpty && hashChecksum == checksum
    }

    private func assertCost(_ cost: UInt) throws {
        guard cost >= Algorithm.minCost && cost <= Algorithm.maxCost else { throw BCryptError.invalidCost(cost) }
    }

    private func assertSalt(_ salt: String) throws {
        if Algorithm(rawValue: String(salt.prefix(Algorithm.revisionCount))) == nil {
            guard salt.count != Algorithm.saltCount else { return }
        } else {
            guard salt.count != Algorithm.revisionCostSaltCount else { return }
        }

        throw BCryptError.invalidSalt(salt)
    }
}

public enum BCryptError: LocalizedError {
    case invalidCost(_ cost: UInt)
    case invalidHash(_ hash: String)
    case invalidPlaintext(_ plaintext: String)
    case invalidSalt(_ salt: String)

    public var errorDescription: String? {
        switch self {
        case .invalidCost(let cost):
            return "The cost \"\(cost)\" must be between \(BCrypt.Algorithm.minCost) and \(BCrypt.Algorithm.maxCost)."
        case .invalidHash(let hash): return "The hash \"\(hash)\" is not a valid BCrypt hash."
        case .invalidPlaintext(let plaintext): return "Can't hash \"\(plaintext)\"."
        case .invalidSalt(let salt): return "The salt \"\(salt)\" is not a valid BCrypt salt."
        }
    }
}

extension BCrypt {
    public enum Algorithm: String, CaseIterable {
        case _2a = "$2a$"
        case _2b = "$2b$"
        case _2y = "$2y$"

        static var checksumCount: Int { 31 }
        static var revisionCount: Int { 4 }
        static var revisionCostSaltCount: Int { 29 }
        static var maxCost: UInt { 31 }
        static var minCost: UInt { 4 }
        static var saltCount: Int { 22 }
    }
}
