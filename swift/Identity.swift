import CryptoKit
import Foundation

/// This phone's identity key (P-256), made once and kept in the Keychain. Its public half goes to the chats (extra 19).
/// The chat's maker uses it to hand each person who stays a new chat key when someone is taken out: sealed with a key
/// only the two of them can work out (ECDH), so the one taken out can't read it, and nobody but the maker can make it.
/// The same as the Android app's Identity.
enum Identity {
    private static let account = "me.identity"
    static let size = Note.identitySize

    private static let key: P256.KeyAgreement.PrivateKey = {
        if let d = Keychain.load(account), let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: d) { return k }
        let k = P256.KeyAgreement.PrivateKey()
        Keychain.save(k.rawRepresentation, for: account)
        return k
    }()

    static var publicKey: Data { key.publicKey.rawRepresentation }

    /// The key between me and `other` for a rekey in a chat (`room`: its old key's) to `member`.
    private static func between(_ other: Data, room: Data, member: UInt32) -> SymmetricKey? {
        guard let pub = try? P256.KeyAgreement.PublicKey(rawRepresentation: other),
              let secret = try? key.sharedSecretFromKeyAgreement(with: pub) else { return nil }
        var info = Data("arke.rekey".utf8)
        withUnsafeBytes(of: member.bigEndian) { info.append(contentsOf: $0) }
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: room, sharedInfo: info, outputByteCount: 32)
    }

    /// Seals 32 bytes (a new chat key; zeros: "you're out") for `member`, whose identity key is `other`.
    static func seal(_ bytes: Data, for member: UInt32, other: Data, room: Data) -> Data? {
        guard bytes.count == 32, let k = between(other, room: room, member: member) else { return nil }
        return try? AES.GCM.seal(bytes, using: k).combined
    }

    /// Opens what the chat's maker (identity key `maker`) sealed for me; nil if it isn't really from them.
    static func open(_ sealed: Data, from maker: Data, me: UInt32, room: Data) -> Data? {
        guard let k = between(maker, room: room, member: me), let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
        return try? AES.GCM.open(box, using: k)
    }
}
