import Foundation
import CryptoKit

/// Generates and validates the 12-word recovery phrase. It uses the BIP-39
/// word list and checksum, which catch most transcription mistakes. The
/// phrase is not a BIP-39 seed: recovery protocol 2 derives from it only the
/// key that wraps the recovery key (see `RecoveryProtocol`).
enum RecoveryPhrase {

    /// Generates a fresh 12-word phrase from 128 bits of
    /// `SecRandomCopyBytes` entropy. Call this once, right after a
    /// successful `bootstrap()`, show the phrase to the customer, and
    /// let `NEXUSSignSDK` register the recovery key wrapped under it, never the
    /// phrase itself.
    static func generate() throws -> [String] {
        var entropy = [UInt8](repeating: 0, count: 16) // 128 bits
        let status = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
        guard status == errSecSuccess else {
            throw NEXUSSignError.randomGenerationFailed(status: status)
        }
        return try words(fromEntropy: entropy)
    }

    /// Trims and lowercases each word and drops empty entries, so pasted or
    /// auto-capitalized input is accepted. Key derivation uses the same rule.
    static func normalized(_ phrase: [String]) -> [String] {
        phrase
            .flatMap { $0.split(whereSeparator: { $0.isWhitespace }) }
            .map { $0.lowercased() }
    }

    /// Checks that a phrase typed during recovery is well-formed (12 known
    /// words, valid checksum) before any network call. This is a typo check,
    /// not a security boundary: whether the phrase is correct is decided by
    /// opening the wrapped recovery key with it (the AES-GCM tag), and Auth
    /// Core accepts only a proof signed with that recovery key.
    static func isWellFormed(_ phrase: [String]) -> Bool {
        let phrase = normalized(phrase)
        guard phrase.count == 12, let wordlist = try? loadWordlist() else {
            return false
        }
        let indices = phrase.compactMap { wordlist.firstIndex(of: $0) }
        guard indices.count == 12 else {
            return false
        }

        var bits = ""
        for index in indices {
            bits += String(index, radix: 2).leftPadded(to: 11)
        }

        let entropyBits = String(bits.prefix(128))
        let checksumBits = String(bits.suffix(4))
        let entropy = Self.bytes(fromBitString: entropyBits)
        let expectedChecksum = Self.checksumBits(forEntropy: entropy)

        return checksumBits == expectedChecksum
    }

    // MARK: - Encoding

    private static func words(fromEntropy entropy: [UInt8]) throws -> [String] {
        let wordlist = try loadWordlist()
        let entropyBits = entropy.map { String($0, radix: 2).leftPadded(to: 8) }.joined()
        let checksum = checksumBits(forEntropy: entropy)
        let allBits = entropyBits + checksum // 128 + 4 = 132 bits = 12 groups of 11

        var result: [String] = []
        var index = allBits.startIndex
        for _ in 0..<12 {
            let end = allBits.index(index, offsetBy: 11)
            let chunk = String(allBits[index..<end])
            guard let wordIndex = Int(chunk, radix: 2), wordIndex < wordlist.count else {
                throw NEXUSSignError.configurationInvalid(detail: "the recovery word list is missing from the SDK bundle")
            }
            result.append(wordlist[wordIndex])
            index = end
        }
        return result
    }

    private static func checksumBits(forEntropy entropy: [UInt8]) -> String {
        let hash = SHA256.hash(data: Data(entropy))
        let firstByte = Array(hash)[0]
        // 128 bits of entropy needs a 4-bit checksum (128 / 32 = 4),
        // per BIP-39: the top 4 bits of SHA-256(entropy).
        return String(firstByte, radix: 2).leftPadded(to: 8).prefix(4).description
    }

    private static func bytes(fromBitString bits: String) -> [UInt8] {
        var result: [UInt8] = []
        var index = bits.startIndex
        while index < bits.endIndex {
            let end = bits.index(index, offsetBy: 8, limitedBy: bits.endIndex) ?? bits.endIndex
            let byteString = String(bits[index..<end]).leftPadded(to: 8)
            result.append(UInt8(byteString, radix: 2) ?? 0)
            index = end
        }
        return result
    }

    /// Loaded once; `static let` initialization is thread-safe.
    private static let wordlist: [String]? = {
        guard let url = Bundle.module.url(forResource: "english", withExtension: "txt"),
              let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }
        let words = contents.split(separator: "\n").map(String.init)
        return words.count == 2048 ? words : nil
    }()

    private static func loadWordlist() throws -> [String] {
        guard let wordlist else { throw NEXUSSignError.configurationInvalid(detail: "the recovery word list is missing from the SDK bundle") }
        return wordlist
    }
}

private extension String {
    func leftPadded(to length: Int) -> String {
        count >= length ? self : String(repeating: "0", count: length - count) + self
    }
}
