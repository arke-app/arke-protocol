package com.miguelgoncalves.arke.model

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * This phone's identity key (P-256), made once and kept by [KeyVault]. Its public half (X and Y, 64 bytes) goes to the
 * chats (extra 19). The chat's maker uses it to hand each person who stays a new chat key when someone is taken out:
 * sealed with a key only the two of them can work out (ECDH, then HKDF-SHA256), so the one taken out can't read it and
 * nobody but the maker can make it. The same as the iPhone app's Identity (CryptoKit).
 */
class Identity internal constructor(private val private: PrivateKey, private val public: ECPublicKey) {
    /** X and Y, 32 bytes each (as CryptoKit's rawRepresentation). */
    val publicKey: ByteArray = fixed(public.w.affineX) + fixed(public.w.affineY)

    private fun between(other: ByteArray, room: ByteArray, member: Long): ByteArray? = runCatching {
        if (other.size != Note.IDENTITY_SIZE) return null
        val point = ECPoint(BigInteger(1, other.copyOfRange(0, 32)), BigInteger(1, other.copyOfRange(32, 64)))
        val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, public.params))
        val secret = KeyAgreement.getInstance("ECDH").apply { init(private); doPhase(pub, true) }.generateSecret()
        // HKDF-SHA256: salt the old chat key's room tag, info "arke.rekey" and the member's id (4 bytes, big-endian).
        val prk = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(room, "HmacSHA256")) }.doFinal(secret)
        val info = "arke.rekey".toByteArray() + byteArrayOf((member shr 24).toByte(), (member shr 16).toByte(), (member shr 8).toByte(), member.toByte())
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }.doFinal(info + byteArrayOf(1))
    }.getOrNull()

    /** Seals 32 bytes (a new chat key; zeros: "you're out") for [member], whose identity key is [other]. */
    fun seal(bytes: ByteArray, member: Long, other: ByteArray, room: ByteArray): ByteArray? {
        val k = between(other, room, member) ?: return null
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce)) }
        return nonce + c.doFinal(bytes)
    }

    /** Opens what the chat's maker (identity key [maker]) sealed for me; null if it isn't really from them. */
    fun open(sealed: ByteArray, maker: ByteArray, me: Long, room: ByteArray): ByteArray? {
        val k = between(maker, room, me) ?: return null
        return runCatching {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, sealed, 0, 12)) }
                .doFinal(sealed, 12, sealed.size - 12)
        }.getOrNull()
    }

    companion object {
        private const val PRIVATE = "identity.private"
        private const val PUBLIC = "identity.public"

        /** This phone's: kept by [vault], made the first time. */
        fun load(vault: KeyVault): Identity {
            val kf = KeyFactory.getInstance("EC")
            val p = vault.loadSecret(PRIVATE)
            val q = vault.loadSecret(PUBLIC)
            if (p != null && q != null) runCatching {
                return Identity(kf.generatePrivate(PKCS8EncodedKeySpec(p)), kf.generatePublic(java.security.spec.X509EncodedKeySpec(q)) as ECPublicKey)
            }
            val g = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            vault.saveSecret(PRIVATE, g.private.encoded)
            vault.saveSecret(PUBLIC, g.public.encoded)
            return Identity(g.private, g.public as ECPublicKey)
        }

        private fun fixed(v: BigInteger): ByteArray {
            val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - b.size) + b
        }
    }
}
