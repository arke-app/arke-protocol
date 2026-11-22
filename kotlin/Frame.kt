package com.miguelgoncalves.arke.model

import com.miguelgoncalves.arke.net.ChatChannel

import android.net.Uri
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

// The same bytes as the iPhone app (Frame.swift): an iPhone and an Android phone read each other's messages.

/**
 * What travels on every network: one sealed chat message. Small enough for one Meshtastic radio packet (233 bytes)
 * and for a text-message link. Any Arke phone can carry it; only people with the chat's key can read it.
 * A photo travels as a frame of its own (version 2, up to 64 KB): over the internet and phones nearby, never the radio.
 */
class Frame(
    /** Short tag of the chat key, so a phone finds its own chats' messages without trying every key. */
    val room: ByteArray,
    val id: Long,
    /** Seconds since 1970. Carriers drop it after this. */
    val expires: Long,
    /** AES-GCM: nonce, ciphertext, tag. The header is authenticated too, so a carrier can't change it unnoticed. */
    val sealed: ByteArray = ByteArray(0),
    /** 1: a message (a Note); 2: a photo, sealed JPEG bytes; 3: a part of a file. */
    val version: Int = VERSION,
) {
    val isPhoto get() = version == PHOTO
    val isFilePart get() = version == FILE_PART
    val isPost get() = version == POST

    /** What a post frame asks to put on the relay: the topic, and the frame (checked against its outside). */
    val posted: Pair<String, Frame>?
        get() {
            if (!isPost || sealed.size <= 12) return null
            val inner = parse(sealed.copyOfRange(12, sealed.size)) ?: return null
            if (inner.isPost || inner.isBig || inner.id xor POST_MASK != id || !inner.room.contentEquals(room)) return null
            return ("arke-" + sealed.copyOf(12).hex()) to inner
        }
    /** A photo or a file part: too big for the radio or SMS. */
    val isBig get() = version != VERSION

    fun header(): ByteArray {
        val w = Bytes()
        w.raw(MAGIC)
        w.u8(version)
        w.raw(room.copyOf(8))
        w.u64(id)
        w.u32(expires)
        return w.bytes()
    }

    fun data(): ByteArray = header() + sealed

    /** The message id as the iPhone app writes it: hexadecimal, no leading zeros. */
    val hexID get() = java.lang.Long.toUnsignedString(id, 16)

    /**
     * For text messages: a web link any messages app makes tappable ("https://arke-app.github.io/m/#<base64url>").
     * Arke opens it itself; without, the page hands what's after the # (it never reaches the website) to the app.
     */
    val link get() = WEB_LINK + data().base64URL()

    override fun equals(other: Any?) = other is Frame && other.data().contentEquals(data())
    override fun hashCode() = id.hashCode()

    companion object {
        val MAGIC = "MC".toByteArray()
        const val VERSION = 1
        const val PHOTO = 2
        const val FILE_PART = 3
        /**
         * A frame handed to a phone nearby to put on the internet relay for its chat (the bridge): 12 bytes the relay
         * topic, then the frame. Whoever posts it can't open it. Id: the frame's id with POST_MASK, so both can be carried.
         */
        const val POST = 4
        const val POST_MASK = 0x5A5A5A5A5A5A5A5AL

        /** [inner], for a phone nearby with the internet to post on [topic] (12 bytes). */
        fun post(inner: Frame, topic: ByteArray) = Frame(inner.room, inner.id xor POST_MASK, inner.expires, topic.copyOf(12) + inner.data(), POST)
        const val LIFETIME = 48 * 3600L
        /** The most a frame can be: phones nearby store frames with a two-byte length. */
        const val MAX_SIZE = 65_535
        /** The most a radio packet carries. */
        const val RADIO_SIZE = 233

        fun parse(data: ByteArray): Frame? {
            val r = Reader(data)
            if (!(r.take(2) ?: return null).contentEquals(MAGIC)) return null
            val version = r.u8()
            if (version != VERSION && version != PHOTO && version != FILE_PART && version != POST) return null
            val room = r.take(8) ?: return null
            val id = r.u64() ?: return null
            val expires = r.u32() ?: return null
            val sealed = r.rest()
            if (sealed.size <= 28) return null
            return Frame(room, id, expires, sealed, version)
        }

        const val WEB_LINK = "https://arke-app.github.io/m/#"
        /** Links made before the name changed from MeetChat to Arke still open. */
        const val OLD_WEB_LINK = "https://meetchat-app.github.io/m/#"

        /** A message link: the web one, or "arke://m/<base64url>" (or the old meetchat:// ones). */
        /** The message a link opens: its last frame (see [allInLink]). */
        fun parseLink(link: String): Frame? = allInLink(link).lastOrNull()

        /** Every frame in a link, oldest first, joined by "." (not in the base64url alphabet): an SMS carries the
         *  earlier SMS messages too, so opening only the last one doesn't lose them. */
        fun allInLink(link: String): List<Frame> {
            val b64 = when {
                link.startsWith("arke://m/") -> link.removePrefix("arke://m/")
                link.startsWith("meetchat://m/") -> link.removePrefix("meetchat://m/")
                link.startsWith(WEB_LINK) -> link.removePrefix(WEB_LINK)
                link.startsWith(OLD_WEB_LINK) -> link.removePrefix(OLD_WEB_LINK)
                else -> return emptyList()
            }
            return b64.trim().split(".").mapNotNull { p -> base64URLDecode(p)?.let(::parse) }
        }

        /** One link for several frames, oldest first. */
        fun link(frames: List<Frame>) = WEB_LINK + frames.joinToString(".") { it.data().base64URL() }
    }
}

/** A place shared in a message. [accuracy] in metres. */
data class Place(val latitude: Double, val longitude: Double, val accuracy: Int) {
    /** Shown by Arke versions that don't know places, and in notifications. */
    val text get() = String.format(java.util.Locale.US, "📍 Location %.5f, %.5f", latitude, longitude)

    fun toJSON() = JSONObject().put("latitude", latitude).put("longitude", longitude).put("accuracy", accuracy)

    companion object {
        fun fromJSON(o: JSONObject?) = o?.let { Place(it.getDouble("latitude"), it.getDouble("longitude"), it.optInt("accuracy")) }
    }
}

/** A map area someone saved for offline use (Offline Maps → Save an Area), shared so the others can save it too
 *  (extra 14): its corners and the deepest zoom kept (14 = every street). */
data class MapArea(val south: Double, val west: Double, val north: Double, val east: Double, val maxZoom: Int) {
    /** Shown by Arke versions that don't know map areas, and in notifications. */
    val text get() = String.format(java.util.Locale.US, "🗺 Map area %.2f, %.2f", (south + north) / 2, (west + east) / 2)

    fun toJSON() = JSONObject().put("south", south).put("west", west).put("north", north).put("east", east).put("maxZoom", maxZoom)

    companion object {
        fun fromJSON(o: JSONObject?) = o?.let { MapArea(it.getDouble("south"), it.getDouble("west"), it.getDouble("north"), it.getDouble("east"), it.optInt("maxZoom", 14)) }
    }
}

/** A photo a message points to: it travels as a frame of its own with this [id] (hex). */
data class PhotoRef(val id: String, val bytes: Int, val width: Int, val height: Int) {
    fun toJSON() = JSONObject().put("id", id).put("bytes", bytes).put("width", width).put("height", height)

    companion object {
        const val TEXT = "📷 Photo"
        fun fromJSON(o: JSONObject?) = o?.let { PhotoRef(it.getString("id"), it.optInt("bytes"), it.optInt("width"), it.optInt("height")) }
    }
}

/** A file a message points to: it travels as [parts] frames, ids [id], [id]+1, … ([id] in hex: the first). */
data class FileRef(val id: String, val name: String, val bytes: Int, val parts: Int) {
    val text get() = "📎 $name"

    fun toJSON() = JSONObject().put("id", id).put("name", name).put("bytes", bytes).put("parts", parts)

    companion object {
        const val MAX_NAME = 40
        const val MAX_BYTES = 1_000_000
        /** File bytes in one part (the rest of the 64 KB frame is header, seal and part number). */
        const val PART_BYTES = 58_000

        fun fromJSON(o: JSONObject?) = o?.let { FileRef(it.getString("id"), it.optString("name"), it.optInt("bytes"), it.optInt("parts")) }

        /** A name that fits, keeping its extension: "A very long report name….pdf" (as on the iPhone). */
        fun fit(name: String): String {
            if (name.toByteArray().size <= MAX_NAME) return name
            val dot = name.lastIndexOf('.')
            val ext = if (dot > 0) name.substring(dot + 1) else ""
            val tail = if (ext.isEmpty() || ext.toByteArray().size > 8) "" else ".$ext"
            var base = if (tail.isEmpty()) name else name.substring(0, dot)
            while (base.isNotEmpty() && base.toByteArray().size + tail.toByteArray().size + 3 > MAX_NAME) base = base.substring(0, base.offsetByCodePoints(base.length, -1))
            return "$base…$tail"
        }
    }
}

/**
 * Something on a chat's map, carried in a message (extra 5): 1 kind, 4 id, 4+4 latitude/longitude (1e-7°),
 * 2 accuracy (m; 65535: unknown), then a short label. The same bytes as the iPhone's Mark.
 */
data class Mark(
    val kind: Kind, val id: Long = 0, val latitude: Double, val longitude: Double,
    val accuracy: Int = 0, val label: String = "",
) {
    enum class Kind(val code: Int) {
        /** Takes pin [id] off the map; id 0: I stopped sharing where I am. */
        REMOVE(0),
        /** Where I am, while I share it (not shown as a message). */
        POSITION(1),
        OK(2), DANGER(3), HELP(4),
        HAZARD(10), SHELTER(11), WATER(12), MEDICAL(13), MEETING_POINT(14), PIN(15),
        /** Themes' pins (ChatTheme): festival 20…, airsoft / paintball 30…, conference 40… */
        STAGE(20), TOILETS(21), BAR(22), FOOD(23), TENT(24), ENTRANCE(25),
        BASE(30), OBJECTIVE(31), ENEMY(32), ALLY(33), SNIPER(34), RESPAWN(35), SAFE_ZONE(36),
        ROOM(40), REGISTRATION(41), COFFEE(42), TALK(43), LUNCH(44), BOOTH(45), WIFI(46);

        val isStatus get() = this == OK || this == DANGER || this == HELP

        val emoji get() = when (this) {
            REMOVE, POSITION -> "📍"
            OK -> "✅"; DANGER -> "⚠️"; HELP -> "🆘"
            HAZARD -> "🔥"; SHELTER -> "🏠"; WATER -> "💧"; MEDICAL -> "⛑️"; MEETING_POINT -> "🚩"; PIN -> "📍"
            STAGE -> "🎤"; TOILETS -> "🚻"; BAR -> "🍺"; FOOD -> "🍔"; TENT -> "⛺"; ENTRANCE -> "🎟️"
            BASE -> "🏰"; OBJECTIVE -> "🎯"; ENEMY -> "❌"; ALLY -> "🛡️"; SNIPER -> "🔭"; RESPAWN -> "♻️"; SAFE_ZONE -> "🏳️"
            ROOM -> "🚪"; REGISTRATION -> "🪪"; COFFEE -> "☕"; TALK -> "🎙️"; LUNCH -> "🍽️"; BOOTH -> "🏷️"; WIFI -> "📶"
        }

        /** In the phone's language (see [tr]). */
        val title get() = tr(when (this) {
            REMOVE -> "Removed"; POSITION -> "Location"
            OK -> "I'm OK"; DANGER -> "I'm in danger"; HELP -> "I need help"
            HAZARD -> "Danger"; SHELTER -> "Shelter"; WATER -> "Water"; MEDICAL -> "First aid"; MEETING_POINT -> "Meeting point"; PIN -> "Pin"
            STAGE -> "Stage"; TOILETS -> "Toilets"; BAR -> "Bar"; FOOD -> "Food"; TENT -> "Tent"; ENTRANCE -> "Entrance"
            BASE -> "Base"; OBJECTIVE -> "Objective"; ENEMY -> "Enemy"; ALLY -> "Ally"; SNIPER -> "Sniper"; RESPAWN -> "Respawn"; SAFE_ZONE -> "Safe zone"
            ROOM -> "Room"; REGISTRATION -> "Registration"; COFFEE -> "Coffee"; TALK -> "Talk"; LUNCH -> "Lunch"; BOOTH -> "Booth"; WIFI -> "Wi‑Fi"
        })
        val isPin get() = code >= 10

        companion object {
            fun of(code: Int) = entries.firstOrNull { it.code == code }
            val statuses = listOf(OK, DANGER, HELP)
            val pins = listOf(PIN, HAZARD, SHELTER, WATER, MEDICAL, MEETING_POINT)
        }
    }

    /** No position with it (a status sent before the phone knew where it was). */
    val hasPlace get() = accuracy != UNKNOWN && !(latitude == 0.0 && longitude == 0.0)
    /** Shown as a message in the chat (a status or a pin), or only on the map. */
    val isShown get() = kind != Kind.REMOVE && kind != Kind.POSITION

    fun toJSON() = JSONObject().put("kind", kind.code).put("id", id).put("latitude", latitude).put("longitude", longitude)
        .put("accuracy", accuracy).put("label", label)

    companion object {
        const val MAX_LABEL = 40
        /** With kind REMOVE: id 0 stops my live location, id 1 takes my status (OK / Danger / Help) off; other ids are pins. */
        const val STOP_SHARING_ID = 0L
        const val CLEAR_STATUS_ID = 1L
        const val UNKNOWN = 65_535
        fun fromJSON(o: JSONObject?) = o?.let { j ->
            Kind.of(j.optInt("kind", -1))?.let { Mark(it, j.optLong("id"), j.getDouble("latitude"), j.getDouble("longitude"), j.optInt("accuracy"), j.optString("label")) }
        }
    }
}

/** An emoji on a message (extra 8): 8 bytes the message's id, then the emoji as a short text (empty: taken off). */
data class Reaction(val to: Long, val emoji: String) {
    companion object {
        const val MAX_EMOJI = 16
        /** The ones offered. */
        val CHOICES = listOf("👍", "❤️", "😂", "😮", "😢", "🙏")
    }
}

/** What's inside a frame. */
/**
 * A chat's three tabs, and the way a message in each goes: SMS only; internet and phones nearby ("Data"); the
 * Meshtastic radio ("Mesh"). A message carries its lane (extra 16), so it shows in the same tab on every phone
 * whichever way it arrived.
 */
/** In this order on screen. NEARBY (phones nearby, 19 Nov) was part of DATA before: older versions show its messages
 *  (code 3, unknown to them) by the way they came. */
enum class Lane(val code: Int) {
    SMS(1), DATA(0), NEARBY(3), MESH(2);
    /** Photos, files and voice messages: the internet and phones nearby only (too big for the radio and SMS). */
    val big get() = this == DATA || this == NEARBY
    companion object { fun of(code: Int?) = entries.firstOrNull { it.code == code } }
}

data class Note(
    val sender: Long, val name: String, val text: String, val sent: Long = System.currentTimeMillis() / 1000,
    val place: Place? = null, val photo: PhotoRef? = null, val file: FileRef? = null,
    /** A delivery confirmation: ids of messages this phone has received (no text; not shown as a message). */
    val receipts: List<Long> = emptyList(),
    /** Something for the chat's map: where I am, how I am, a pin, or a pin taken off. */
    val mark: Mark? = null,
    /** "I've joined the chat", sent once by a phone that joins. */
    val joined: Boolean = false,
    /** The sender's phone number (Settings), so the others can text them: when they join, when it changes, and to
     *  someone who just joined. */
    val number: String? = null,
    /** An emoji on someone's message (empty: taken off). Not a message itself. */
    val reaction: Reaction? = null,
    /** A reply to this message (its id). */
    val replyTo: Long? = null,
    /** New text for one of my messages (its id): not a message itself. */
    val edits: Long? = null,
    /** One of my messages, deleted for everyone (its id): not a message itself. */
    val deletes: Long? = null,
    /** Passed on from another chat. */
    val forwarded: Boolean = false,
    /** The sender's colour (0–6, Settings → Appearance), for their name and their dot on the map. Sent with their number. */
    val colour: Int? = null,
    /** A map area to save for offline use. */
    val area: MapArea? = null,
    /** With a confirmation: of those messages, the ones this phone got by SMS and passed on to the chat, so the others
     *  show who shared them (extra 15). */
    val carried: List<Long> = emptyList(),
    /** The tab it was written in, so the way it was sent (extra 16). */
    val lane: Lane? = null,
    /** "I've left the chat" (extra 17), the last thing a phone sends to a chat it deletes: the others see "… left" and
     *  take them off their list of people. */
    val left: Boolean = false,
    /** With a location sent (📍 My Location): the networks the sender could use right then (extra 18; [Reach]). */
    val reach: Int? = null,
    /** The sender's identity key (extra 19): P-256, 64 bytes, so the chat's maker can hand them a new chat key only
     *  they can open ([Rekey]). Sent with their number, and when they join. */
    val identity: ByteArray? = null,
    /** With the identity: "I made this chat" (extra 20). Only its maker can take someone out of it. */
    val owner: Boolean = false,
    /** The chat's maker took someone out (extra 21): the chat's new key, for each who stays, that only they can open. */
    val rekey: Rekey? = null,
    /** "Don't use my number in this chat any more" (extra 22): I stopped sharing it here (the chat's info). */
    val noNumber: Boolean = false,
    /** The whole map at once (extra 23, maybe several): every pin and everyone's last place, for someone only SMS reaches. */
    val snapshot: MapSnapshot? = null,
) {
    fun packed(): ByteArray {
        val w = Bytes()
        w.u8(1)
        w.u32(sender)
        w.u32(sent)
        w.text(name, MAX_NAME)
        w.text(text, MAX_TEXT)
        // Extras after the text, each a type and length byte (older versions stop reading at the text).
        place?.let { p ->
            w.u8(1); w.u8(10)
            w.u32(Math.round(p.latitude * 1e7).coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()))
            w.u32(Math.round(p.longitude * 1e7).coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()))
            w.u16(p.accuracy.coerceIn(0, 65535))
        }
        photo?.let { p ->
            val id = java.lang.Long.parseUnsignedLong(p.id, 16)
            w.u8(2); w.u8(16)
            w.u64(id)
            w.u32(p.bytes.toLong().coerceAtLeast(0))
            w.u16(p.width.coerceIn(0, 65535))
            w.u16(p.height.coerceIn(0, 65535))
        }
        file?.let { f ->
            val e = Bytes()
            e.u64(java.lang.Long.parseUnsignedLong(f.id, 16))
            e.u32(f.bytes.toLong().coerceAtLeast(0))
            e.u16(f.parts.coerceIn(0, 65535))
            e.text(f.name, FileRef.MAX_NAME)
            val b = e.bytes()
            w.u8(3); w.u8(b.size); w.raw(b)
        }
        if (receipts.isNotEmpty()) {
            val ids = receipts.take(MAX_RECEIPTS)
            w.u8(4); w.u8(1 + 8 * ids.size); w.u8(ids.size)
            ids.forEach { w.u64(it) }
        }
        mark?.let { m ->
            val e = Bytes()
            e.u8(m.kind.code)
            e.u32(m.id)
            e.u32(Math.round(m.latitude * 1e7).coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()))
            e.u32(Math.round(m.longitude * 1e7).coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()))
            e.u16(m.accuracy.coerceIn(0, 65535))
            e.text(m.label, Mark.MAX_LABEL)
            val b = e.bytes()
            w.u8(5); w.u8(b.size); w.raw(b)
        }
        if (joined) { w.u8(6); w.u8(0) }
        number?.takeIf { it.isNotEmpty() }?.let { n ->
            val e = Bytes()
            e.text(n, MAX_NUMBER)
            val b = e.bytes()
            w.u8(7); w.u8(b.size); w.raw(b)
        }
        reaction?.let { r ->
            val e = Bytes()
            e.u64(r.to)
            e.text(r.emoji, Reaction.MAX_EMOJI)
            val b = e.bytes()
            w.u8(8); w.u8(b.size); w.raw(b)
        }
        listOf(9 to replyTo, 10 to edits, 11 to deletes).forEach { (type, id) -> if (id != null) { w.u8(type); w.u8(8); w.u64(id) } }
        if (forwarded) { w.u8(12); w.u8(0) }
        if (colour != null) { w.u8(13); w.u8(1); w.u8(colour) }
        area?.let { a ->
            w.u8(14); w.u8(17)
            for (v in listOf(a.south, a.west, a.north, a.east)) w.u32(Math.round(v * 1e7).toInt().toLong() and 0xFFFFFFFFL)
            w.u8(a.maxZoom.coerceIn(0, 255))
        }
        if (carried.isNotEmpty()) {
            val ids = carried.take(MAX_RECEIPTS)
            w.u8(15); w.u8(1 + 8 * ids.size); w.u8(ids.size)
            ids.forEach { w.u64(it) }
        }
        lane?.let { w.u8(16); w.u8(1); w.u8(it.code) }
        if (left) { w.u8(17); w.u8(0) }
        reach?.let { w.u8(18); w.u8(1); w.u8(it) }
        identity?.takeIf { it.size == IDENTITY_SIZE }?.let { w.u8(19); w.u8(it.size); w.raw(it) }
        if (owner) { w.u8(20); w.u8(0) }
        if (noNumber) { w.u8(22); w.u8(0) }
        snapshot?.chunks()?.forEach { c -> w.u8(23); w.u8(c.size); w.raw(c) }
        rekey?.let { k ->
            val e = Bytes()
            e.u32(k.removed)
            k.keys.take(Rekey.PER_NOTE).filter { it.second.size == Rekey.SEALED_SIZE }.forEach { (id, sealed) -> e.u32(id); e.raw(sealed) }
            val b = e.bytes()
            w.u8(21); w.u8(b.size); w.raw(b)
        }
        return w.bytes()
    }

    companion object {
        const val MAX_NAME = 20
        const val MAX_NUMBER = 20
        /** An identity key's size (extra 19): P-256, X and Y, 32 bytes each. */
        const val IDENTITY_SIZE = 64
        /** How many messages one confirmation covers. */
        const val MAX_RECEIPTS = 8
        /** Keeps the whole frame inside one radio packet. */
        const val MAX_TEXT = 140

        fun unpack(data: ByteArray): Note? {
            val r = Reader(data)
            if (r.u8() != 1) return null
            val sender = r.u32() ?: return null
            val sent = r.u32() ?: return null
            val name = r.text() ?: return null
            val text = r.text() ?: return null
            var place: Place? = null
            var photo: PhotoRef? = null
            var file: FileRef? = null
            var receipts = emptyList<Long>()
            var mark: Mark? = null
            var joined = false
            var number: String? = null
            var reaction: Reaction? = null
            var replyTo: Long? = null
            var edits: Long? = null
            var deletes: Long? = null
            var forwarded = false
            var colour: Int? = null
            var area: MapArea? = null
            var carried = emptyList<Long>()
            var lane: Lane? = null
            var left = false
            var reach: Int? = null
            var identity: ByteArray? = null
            var owner = false
            var rekey: Rekey? = null
            var noNumber = false
            var snapshot: MapSnapshot? = null
            while (true) {
                val type = r.u8() ?: break
                val n = r.u8() ?: break
                val v = r.take(n) ?: break
                val e = Reader(v)
                when (type) {
                    1 -> {
                        val lat = e.u32(); val lon = e.u32(); val acc = e.u16()
                        if (lat != null && lon != null && acc != null) place = Place(lat.toInt() / 1e7, lon.toInt() / 1e7, acc)
                    }
                    2 -> {
                        val id = e.u64(); val bytes = e.u32(); val w = e.u16(); val h = e.u16()
                        if (id != null && bytes != null && w != null && h != null) photo = PhotoRef(java.lang.Long.toUnsignedString(id, 16), bytes.toInt(), w, h)
                    }
                    3 -> {
                        val id = e.u64(); val bytes = e.u32(); val parts = e.u16(); val name = e.text()
                        if (id != null && bytes != null && parts != null && name != null) file = FileRef(java.lang.Long.toUnsignedString(id, 16), name, bytes.toInt(), parts)
                    }
                    4 -> {
                        val n = e.u8()
                        if (n != null) receipts = (0 until n).mapNotNull { e.u64() }
                    }
                    5 -> {
                        val kind = e.u8()?.let { Mark.Kind.of(it) }; val id = e.u32(); val lat = e.u32(); val lon = e.u32(); val acc = e.u16()
                        if (kind != null && id != null && lat != null && lon != null && acc != null)
                            mark = Mark(kind, id, lat.toInt() / 1e7, lon.toInt() / 1e7, acc, e.text() ?: "")
                    }
                    6 -> joined = true
                    7 -> number = e.text()?.ifEmpty { null }
                    8 -> { val to = e.u64(); val emoji = e.text(); if (to != null && emoji != null) reaction = Reaction(to, emoji) }
                    9 -> replyTo = e.u64()
                    10 -> edits = e.u64()
                    11 -> deletes = e.u64()
                    12 -> forwarded = true
                    13 -> colour = e.u8()?.takeIf { it < 7 }
                    14 -> {
                        val s = e.u32(); val w = e.u32(); val n = e.u32(); val ea = e.u32(); val z = e.u8()
                        if (s != null && w != null && n != null && ea != null && z != null)
                            area = MapArea(s.toInt() / 1e7, w.toInt() / 1e7, n.toInt() / 1e7, ea.toInt() / 1e7, z)
                    }
                    15 -> {
                        val c = e.u8()
                        if (c != null) carried = (0 until c).mapNotNull { e.u64() }
                    }
                    16 -> lane = Lane.of(e.u8())
                    17 -> left = true
                    18 -> reach = e.u8()
                    19 -> if (v.size == IDENTITY_SIZE) identity = v
                    20 -> owner = true
                    22 -> noNumber = true
                    23 -> snapshot = (snapshot ?: MapSnapshot()).read(v)
                    21 -> e.u32()?.let { removed ->
                        val keys = mutableListOf<Pair<Long, ByteArray>>()
                        while (true) {
                            val id = e.u32() ?: break
                            val sealed = e.take(Rekey.SEALED_SIZE) ?: break
                            keys.add(id to sealed)
                        }
                        rekey = Rekey(removed, keys)
                    }
                }
            }
            return Note(sender, name, text, sent, place, photo, file, receipts, mark, joined, number, reaction, replyTo, edits, deletes, forwarded, colour, area, carried, lane, left, reach, identity, owner, rekey, noNumber, snapshot)
        }

        /** Cuts text to whole characters that fit in a message. */
        fun fit(s: String) = cut(s, MAX_TEXT)
    }
}

/** The networks someone could use when they sent where they are (extra 18): bits for SMS, the internet, phones nearby, the radio. */
object Reach {
    const val SMS = 1
    const val INTERNET = 2
    const val NEARBY = 4
    const val RADIO = 8
}

/**
 * The chat's maker took [removed] out of the chat (extra 21): 4 bytes them, then for each person who stays (and for
 * the one removed: 32 zero bytes, so they know it's really the maker) 4 bytes their id and the new chat key sealed for
 * them alone (AES-GCM, 60 bytes) with a key only the maker and they can work out ([Identity]). Two a note: one radio packet.
 * The same bytes as the iPhone app's Rekey.
 */
class Rekey(val removed: Long, val keys: List<Pair<Long, ByteArray>>) {
    companion object {
        const val SEALED_SIZE = 60
        const val PER_NOTE = 2
    }
}

/** A chat's secret: 32 random bytes, shared by QR code or invite link. Everything else is worked out from it. */
class ChatKey private constructor(val raw: ByteArray) {
    /** HKDF-SHA256 with no salt, like CryptoKit's HKDF<SHA256>.deriveKey(inputKeyMaterial:info:outputByteCount: 32). */
    private fun derive(label: String): ByteArray {
        val extract = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(ByteArray(32), "HmacSHA256")) }.doFinal(raw)
        val expand = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(extract, "HmacSHA256")) }
        expand.update("arke.$label".toByteArray())
        expand.update(1)
        return expand.doFinal()
    }

    private val sealKey by lazy { derive("seal") }
    val room: ByteArray by lazy { derive("room").copyOf(8) }

    /** The internet relay's topic: says nothing about the key, and only people with the key can work it out. */
    val topicBytes by lazy { derive("topic").copyOf(12) }
    val topic by lazy { "arke-" + topicBytes.hex() }

    /** Shown so people can check they have the same chat: same code, same key. */
    val safetyCode by lazy {
        val n = derive("check").copyOf(4).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) } % 1_000_000
        "%03d %03d".format(n / 1000, n % 1000)
    }

    fun seal(note: Note, id: Long = randomID(), expires: Long = note.sent + Frame.LIFETIME): Frame {
        val f = Frame(room, id, expires)
        // Laid out like CryptoKit's "combined": nonce (12) + ciphertext + tag (16).
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(f.header())
        return Frame(room, id, expires, nonce + cipher.doFinal(note.packed()))
    }

    /** A photo's JPEG bytes, sealed as a frame of its own. */
    fun sealPhoto(jpeg: ByteArray, id: Long, sent: Long = System.currentTimeMillis() / 1000): Frame {
        val f = Frame(room, id, sent + Frame.LIFETIME, version = Frame.PHOTO)
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(f.header())
        return Frame(room, id, f.expires, nonce + cipher.doFinal(jpeg), Frame.PHOTO)
    }

    /** One part of a file: its number, how many there are, and its bytes, sealed as a frame of its own (id: the file's + [index]). */
    fun sealFilePart(bytes: ByteArray, index: Int, count: Int, file: Long, sent: Long = System.currentTimeMillis() / 1000): Frame {
        val f = Frame(room, file + index, sent + Frame.LIFETIME, version = Frame.FILE_PART)
        val w = Bytes(); w.u16(index); w.u16(count); w.raw(bytes)
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(f.header())
        return Frame(room, f.id, f.expires, nonce + cipher.doFinal(w.bytes()), Frame.FILE_PART)
    }

    class Part(val file: Long, val index: Int, val count: Int, val bytes: ByteArray)

    fun openFilePart(f: Frame): Part? {
        if (!f.isFilePart || !f.room.contentEquals(room)) return null
        val d = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, f.sealed, 0, 12))
            cipher.updateAAD(f.header())
            cipher.doFinal(f.sealed, 12, f.sealed.size - 12)
        } catch (e: Exception) {
            return null
        }
        val r = Reader(d)
        val i = r.u16() ?: return null
        val n = r.u16() ?: return null
        if (i >= n) return null
        return Part(f.id - i, i, n, r.rest())
    }

    fun openPhoto(f: Frame): ByteArray? {
        if (!f.isPhoto || !f.room.contentEquals(room)) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, f.sealed, 0, 12))
            cipher.updateAAD(f.header())
            cipher.doFinal(f.sealed, 12, f.sealed.size - 12)
        } catch (e: Exception) {
            null
        }
    }

    fun open(f: Frame): Note? {
        if (f.isBig || !f.room.contentEquals(room)) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sealKey, "AES"), GCMParameterSpec(128, f.sealed, 0, 12))
            cipher.updateAAD(f.header())
            Note.unpack(cipher.doFinal(f.sealed, 12, f.sealed.size - 12))
        } catch (e: Exception) {
            null
        }
    }

    override fun equals(other: Any?) = other is ChatKey && other.raw.contentEquals(raw)
    override fun hashCode() = raw.contentHashCode()

    companion object {
        private val random = SecureRandom()

        fun of(raw: ByteArray): ChatKey? = if (raw.size == 32) ChatKey(raw.copyOf()) else null
        fun random() = ChatKey(ByteArray(32).also { random.nextBytes(it) })

        /** Any 64-bit number but 0. */
        fun randomID(): Long {
            var id = 0L
            while (id == 0L) id = random.nextLong()
            return id
        }
    }
}

/** How to join a chat: "https://arke-app.github.io/join/#k=<key>&n=<chat name>" in the QR code and the invite link —
 *  tappable in WhatsApp, SMS and any app, and it opens Arke straight away with no internet (a verified App Link, as the
 *  SMS messages' /m/ links). After the # it never reaches the website. "arke://join?…" (and old meetchat://) still work. */
/** [channel]: the chat's radio channel, so everyone with a radio uses the same one. */
/** [server] ("s"): the chat's relay server, when it isn't the default one, so everyone uses the same one. */
/** [owner]: the identity key (base64url) of the chat's maker ("o"): only they can take people out, and a new key must come from them. */
data class Invite(val key: ChatKey, val name: String, val channel: ChatChannel = ChatChannel.Arke, val server: String? = null, val owner: String? = null,
                  /** The chat's theme ("t"), when it isn't Emergency: everyone who joins gets its pins. */
                  val theme: ChatTheme = ChatTheme.EMERGENCY) {
    val url get() = WEB_LINK + "k=${key.raw.base64URL()}&n=" + URLEncoder.encode(name, "UTF-8").replace("+", "%20") +
        (theme.inviteCode?.let { "&t=$it" } ?: "") +
        (channel.invite?.let { "&r=" + URLEncoder.encode(it, "UTF-8").replace("+", "%20") } ?: "") +
        (server?.let { "&s=" + URLEncoder.encode(it, "UTF-8").replace("+", "%20") } ?: "") +
        (owner?.let { "&o=$it" } ?: "")

    /** The link at most [max] bytes long, to go in a chat message: the key and the name always; the maker, the server
     *  and the radio channel only as they fit (without the maker it's learnt from them later; 19 Nov). */
    fun url(max: Int): String {
        fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        var out = WEB_LINK + "k=${key.raw.base64URL()}&n=" + enc(name) + (theme.inviteCode?.let { "&t=$it" } ?: "")
        for (extra in listOfNotNull(owner?.let { "&o=$it" }, server?.let { "&s=" + enc(it) }, channel.invite?.let { "&r=" + enc(it) }))
            if ((out + extra).toByteArray().size <= max) out += extra
        return out
    }

    companion object {
        const val WEB_LINK = "https://arke-app.github.io/join/#"

        fun parse(url: String): Invite? {
            var s = url.trim()
            // The web link: what's after the # is the invite.
            if (s.startsWith("https://arke-app.github.io/join")) s = "arke://join?" + (s.substringAfter('#', "").ifEmpty { return null })
            if (!s.startsWith("arke://join?") && !s.startsWith("meetchat://join?")) return null
            val query = s.substringAfter('?').split('&').mapNotNull {
                val i = it.indexOf('=')
                if (i < 0) null else it.substring(0, i) to runCatching { URLDecoder.decode(it.substring(i + 1).replace("+", "%2B"), "UTF-8") }.getOrNull()
            }.toMap()
            val key = query["k"]?.let(::base64URLDecode)?.let(ChatKey::of) ?: return null
            // Only web addresses: anything else and the chat stays on the default server.
            val server = query["s"]?.let(com.miguelgoncalves.arke.net.Relay::clean)?.takeIf {
                val u = runCatching { java.net.URI(it) }.getOrNull()
                (u?.scheme == "https" || u?.scheme == "http") && u.host != null && it != com.miguelgoncalves.arke.net.Relay.DEFAULT_SERVER && it != com.miguelgoncalves.arke.net.Relay.OLD_DEFAULT_SERVER
            }
            val owner = query["o"]?.takeIf { base64URLDecode(it)?.size == Note.IDENTITY_SIZE }
            return Invite(key, query["n"]?.takeIf { it.isNotEmpty() } ?: "Chat", ChatChannel.fromInvite(query["r"]), server, owner, ChatTheme.fromInvite(query["t"]))
        }

        fun parse(uri: Uri) = parse(uri.toString())
    }
}

/** Text cut to whole characters that fit in `max` UTF-8 bytes. */
fun cut(s: String, max: Int): String {
    var c = s
    while (c.toByteArray().size > max) c = c.substring(0, c.offsetByCodePoints(c.length, -1))
    return c
}

/**
 * A chat's whole map in one message (extra 23), so someone only SMS reaches catches up on what changed on Data:
 * every pin, the pins taken off lately, and everyone's last place and status. Items one after another, each starting
 * with its type: 1 pin (kind, id, latitude, longitude, who put it, label), 2 person (id, latitude, longitude, minutes
 * before the message, status or 0, name), 3 pin taken off (id). Split over extras of at most 255 bytes. Same bytes
 * as the iPhone's MapSnapshot.
 */
data class MapSnapshot(val pins: List<Pin> = emptyList(), val people: List<Person> = emptyList(), val removed: List<Long> = emptyList()) {
    data class Pin(val kind: Mark.Kind, val id: Long, val latitude: Double, val longitude: Double, val sender: Long, val label: String)
    data class Person(val id: Long, val latitude: Double, val longitude: Double, val minutesAgo: Int, val status: Mark.Kind?, val name: String)

    val isEmpty get() = pins.isEmpty() && people.isEmpty() && removed.isEmpty()

    private fun coord(w: Bytes, v: Double) = w.u32(Math.round(v * 1e7).coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()))

    /** Each item's bytes, packed into extras of at most 255 bytes. */
    fun chunks(): List<ByteArray> {
        val items = mutableListOf<ByteArray>()
        for (p in pins) items += Bytes().apply { u8(1); u8(p.kind.code); u32(p.id); coord(this, p.latitude); coord(this, p.longitude); u32(p.sender); text(p.label, MAX_LABEL) }.bytes()
        for (p in people) items += Bytes().apply { u8(2); u32(p.id); coord(this, p.latitude); coord(this, p.longitude); u16(p.minutesAgo.coerceIn(0, 65535)); u8(p.status?.code ?: 0); text(p.name, MAX_NAME) }.bytes()
        for (id in removed) items += Bytes().apply { u8(3); u32(id) }.bytes()
        val out = mutableListOf<ByteArray>()
        var cur = java.io.ByteArrayOutputStream()
        for (i in items) {
            if (cur.size() + i.size > 255) { out += cur.toByteArray(); cur = java.io.ByteArrayOutputStream() }
            cur.write(i)
        }
        if (cur.size() > 0) out += cur.toByteArray()
        return out
    }

    /** Adds the items in one extra. */
    fun read(chunk: ByteArray): MapSnapshot {
        val r = Reader(chunk)
        val pins = pins.toMutableList(); val people = people.toMutableList(); val removed = removed.toMutableList()
        fun coord(): Double? = r.u32()?.let { it.toInt() / 1e7 }
        loop@ while (true) {
            when (r.u8() ?: break@loop) {
                1 -> {
                    val k = r.u8(); val id = r.u32(); val lat = coord(); val lon = coord(); val by = r.u32(); val label = r.text()
                    if (k == null || id == null || lat == null || lon == null || by == null || label == null) break@loop
                    Mark.Kind.of(k)?.takeIf { it.code >= 10 }?.let { pins += Pin(it, id, lat, lon, by, label) }
                }
                2 -> {
                    val id = r.u32(); val lat = coord(); val lon = coord(); val ago = r.u16(); val st = r.u8(); val name = r.text()
                    if (id == null || lat == null || lon == null || ago == null || st == null || name == null) break@loop
                    people += Person(id, lat, lon, ago, Mark.Kind.of(st)?.takeIf { it.isStatus }, name)
                }
                3 -> removed += (r.u32() ?: break@loop)
                else -> break@loop
            }
        }
        return MapSnapshot(pins, people, removed)
    }

    companion object {
        const val MAX_PINS = 30
        const val MAX_REMOVED = 10
        const val MAX_LABEL = 16
        const val MAX_NAME = 12
    }
}

/** Little-endian bytes out, for the compact message format. */
class Bytes {
    private val out = java.io.ByteArrayOutputStream()
    fun u8(v: Int) = out.write(v and 0xFF)
    fun u16(v: Int) { u8(v); u8(v shr 8) }
    fun u32(v: Long) { for (i in 0 until 4) u8((v shr (8 * i)).toInt()) }
    fun u64(v: Long) { for (i in 0 until 8) u8((v ushr (8 * i)).toInt()) }
    fun raw(b: ByteArray) = out.write(b)

    /** Text cut to whole characters that fit in `max` bytes. */
    fun text(s: String, max: Int) {
        val b = cut(s, max).toByteArray()
        u8(b.size)
        raw(b)
    }

    fun bytes(): ByteArray = out.toByteArray()
}

/** Little-endian bytes in. */
class Reader(private val data: ByteArray) {
    private var at = 0
    fun take(n: Int): ByteArray? = if (at + n <= data.size) data.copyOfRange(at, at + n).also { at += n } else null
    fun u8(): Int? = take(1)?.let { it[0].toInt() and 0xFF }
    fun u16(): Int? = take(2)?.let { (it[0].toInt() and 0xFF) or ((it[1].toInt() and 0xFF) shl 8) }
    fun u32(): Long? = take(4)?.let { b -> (0 until 4).fold(0L) { acc, i -> acc or ((b[i].toLong() and 0xFF) shl (8 * i)) } }
    fun u64(): Long? = take(8)?.let { b -> (0 until 8).fold(0L) { acc, i -> acc or ((b[i].toLong() and 0xFF) shl (8 * i)) } }
    fun text(): String? { val n = u8() ?: return null; return take(n)?.toString(Charsets.UTF_8) }
    fun rest(): ByteArray = if (at < data.size) data.copyOfRange(at, data.size) else ByteArray(0)
}

fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/** Base64 for links, without padding (java.util.Base64 needs Android 8). */
fun ByteArray.base64URL(): String {
    val sb = StringBuilder()
    var i = 0
    while (i < size) {
        val b0 = this[i].toInt() and 0xFF
        val b1 = if (i + 1 < size) this[i + 1].toInt() and 0xFF else 0
        val b2 = if (i + 2 < size) this[i + 2].toInt() and 0xFF else 0
        sb.append(B64[b0 shr 2]).append(B64[((b0 and 3) shl 4) or (b1 shr 4)])
        if (i + 1 < size) sb.append(B64[((b1 and 15) shl 2) or (b2 shr 6)])
        if (i + 2 < size) sb.append(B64[b2 and 63])
        i += 3
    }
    return sb.toString()
}

fun base64URLDecode(s: String): ByteArray? {
    val clean = s.trim().trimEnd('=').replace('+', '-').replace('/', '_')
    val out = java.io.ByteArrayOutputStream()
    var buf = 0
    var bits = 0
    for (c in clean) {
        val v = B64.indexOf(c)
        if (v < 0) return null
        buf = (buf shl 6) or v
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((buf shr bits) and 0xFF)
        }
    }
    return out.toByteArray()
}

/** What a phone nearby carries, sent when two phones link so each sends only what the other lacks:
 *  "MH" and the frame ids, 8 bytes each. Older versions read it as a broken frame and drop it. */
object Have {
    private val MAGIC = "MH".toByteArray()

    fun data(ids: List<Long>): ByteArray {
        val b = java.nio.ByteBuffer.allocate(2 + 8 * ids.size)
        b.put(MAGIC)
        ids.forEach { b.putLong(it) }
        return b.array()
    }

    fun ids(data: ByteArray): Set<Long>? {
        if (data.size < 2 || data[0] != MAGIC[0] || data[1] != MAGIC[1] || (data.size - 2) % 8 != 0) return null
        val b = java.nio.ByteBuffer.wrap(data, 2, data.size - 2)
        return (0 until (data.size - 2) / 8).map { b.long }.toSet()
    }
}
