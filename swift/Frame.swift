import CryptoKit
import Foundation

/// What travels on every network: one sealed chat message. Small enough for one Meshtastic radio packet (233 bytes)
/// and for a text-message link. Any Arke phone can carry it; only people with the chat's key can read it.
/// A photo travels as a frame of its own (version 2, up to 64 KB), a file as parts of up to 58 KB (version 3):
/// over the internet and phones nearby, never the radio.
struct Frame: Hashable {
    /// Short tag of the chat key, so a phone finds its own chats' messages without trying every key.
    var room: Data
    var id: UInt64
    /// Carriers drop it after this.
    var expires: Date
    /// AES-GCM: nonce, ciphertext, tag. The header is authenticated too, so a carrier can't change it unnoticed.
    var sealed: Data
    /// 1: a message (a Note); 2: a photo, sealed JPEG bytes; 3: a part of a file.
    var version: UInt8 = Self.version

    static let magic = Data("MC".utf8)
    static let version: UInt8 = 1
    static let photo: UInt8 = 2
    static let filePart: UInt8 = 3
    /// A frame handed to a phone nearby to put on the internet relay for its chat (the bridge): 12 bytes the relay
    /// topic, then the frame. Whoever posts it can't open it. Id: the frame's id with `postMask`, so both can be carried.
    static let post: UInt8 = 4
    static let postMask: UInt64 = 0x5A5A_5A5A_5A5A_5A5A
    /// The most a frame can be: phones nearby store frames with a two-byte length.
    static let maxSize = 65_535
    /// The most a radio packet carries.
    static let radioSize = 233

    var isPhoto: Bool { version == Self.photo }
    var isFilePart: Bool { version == Self.filePart }
    var isPost: Bool { version == Self.post }

    /// `inner`, for a phone nearby with the internet to post on `topic` (12 bytes).
    static func post(_ inner: Frame, topic: Data) -> Frame {
        Frame(room: inner.room, id: inner.id ^ postMask, expires: inner.expires, sealed: Data(topic.prefix(12)) + inner.data, version: post)
    }

    /// What a post frame asks to put on the relay: the topic, and the frame (checked against its outside).
    var posted: (topic: String, frame: Frame)? {
        guard isPost, sealed.count > 12, let inner = Frame(data: Data(sealed.dropFirst(12))), !inner.isPost, !inner.isBig,
              inner.id ^ Self.postMask == id, inner.room == room else { return nil }
        return ("arke-" + Data(sealed.prefix(12)).hex, inner)
    }
    /// A photo or a file part: too big for the radio or SMS.
    var isBig: Bool { version != Self.version }
    static let lifetime: TimeInterval = 48 * 3600

    var header: Data {
        var w = Bytes()
        w.data.append(Self.magic)
        w.u8(version)
        w.data.append(room.prefix(8))
        w.u64(id)
        w.u32(UInt32(expires.timeIntervalSince1970))
        return w.data
    }

    var data: Data { header + sealed }

    init(room: Data, id: UInt64, expires: Date, sealed: Data, version: UInt8 = Frame.version) {
        self.room = room; self.id = id; self.expires = expires; self.sealed = sealed; self.version = version
    }

    init?(data: Data) {
        var r = Bytes(data)
        guard r.take(2) == Self.magic, let v = r.u8(), v == Self.version || v == Self.photo || v == Self.filePart || v == Self.post,
              let room = r.take(8), let id = r.u64(), let exp = r.u32() else { return nil }
        version = v
        self.room = room
        self.id = id
        expires = Date(timeIntervalSince1970: TimeInterval(exp))
        sealed = r.rest
        guard sealed.count > 28 else { return nil }
    }

    /// For text messages: a web link any messages app makes tappable ("https://arke-app.github.io/m/#<base64url>").
    /// The page hands what's after the # (it never reaches the website) to the app as "arke://m/<base64url>".
    var link: URL { URL(string: Self.webLink + data.base64URL)! }

    static let webLink = "https://arke-app.github.io/m/#"
    /// Links made before the name changed from MeetChat to Arke still open.
    static let oldWebLink = "https://meetchat-app.github.io/m/#"
    static let schemes: Set<String> = ["arke", "meetchat"]

    /// A message link: the web one, or "arke://m/<base64url>" (or the old meetchat:// ones).
    /// The message a link opens: its last frame (see `all`).
    init?(link: URL) {
        guard let f = Self.all(link: link).last else { return nil }
        self = f
    }

    /// One link for several frames, oldest first, joined by "." (not in the base64url alphabet): an SMS carries the
    /// earlier SMS messages too, so opening only the last one doesn't lose them.
    static func link(_ frames: [Frame]) -> URL {
        URL(string: webLink + frames.map(\.data.base64URL).joined(separator: "."))!
    }

    /// Every frame in a link (most links have one).
    static func all(link: URL) -> [Frame] {
        let b64: String
        if let s = link.scheme, schemes.contains(s), link.host == "m" {
            b64 = String(link.path.dropFirst())
        } else if let web = [webLink, oldWebLink].first(where: { link.absoluteString.hasPrefix($0) }) {
            b64 = String(link.absoluteString.dropFirst(web.count))
        } else {
            return []
        }
        return b64.split(separator: ".").compactMap { Data(base64URL: String($0)).flatMap { Frame(data: $0) } }
    }
}

/// What a phone nearby carries, sent when two phones link so each sends only what the other lacks:
/// "MH" and the frame ids, 8 bytes each. Older versions read it as a broken frame and drop it.
/// The same bytes as the Android app's Have.
enum Have {
    static let magic = Data("MH".utf8)
    /// How long to wait for a new neighbour's list before sending it everything.
    static let wait: TimeInterval = 4

    static func data(_ ids: [UInt64]) -> Data {
        var d = magic
        for id in ids { withUnsafeBytes(of: id.bigEndian) { d.append(contentsOf: $0) } }
        return d
    }

    static func ids(_ data: Data) -> Set<UInt64>? {
        let d = Data(data)
        guard d.count >= 2, d.prefix(2) == magic, (d.count - 2) % 8 == 0 else { return nil }
        return Set(stride(from: 2, to: d.count, by: 8).map { i in d[i..<i + 8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) } })
    }
}

/// A place shared in a message.
struct Place: Codable, Equatable {
    var latitude: Double
    var longitude: Double
    /// Metres.
    var accuracy: Int

    /// Shown by Arke versions that don't know places, and in notifications.
    var text: String { String(format: "📍 Location %.5f, %.5f", latitude, longitude) }
}

/// A map area someone saved for offline use (Offline Maps → Save an Area), shared so the others can save it too
/// (extra 14): its corners and the deepest zoom kept (14 = every street).
struct MapArea: Codable, Equatable {
    var south: Double
    var west: Double
    var north: Double
    var east: Double
    var maxZoom: Int

    /// Shown by Arke versions that don't know map areas, and in notifications.
    var text: String { String(format: "🗺 Map area %.2f, %.2f", (south + north) / 2, (west + east) / 2) }
}

/// A photo a message points to: it travels as a frame of its own with this id.
struct PhotoRef: Codable, Equatable {
    /// The photo frame's id, in hex.
    var id: String
    var bytes: Int
    var width: Int
    var height: Int

    static let text = "📷 Photo"
}

/// A file a message points to: it travels as `parts` frames, ids `id`, `id`+1, … (in hex: the first).
struct FileRef: Codable, Equatable {
    var id: String
    var name: String
    var bytes: Int
    var parts: Int

    static let maxName = 40
    static let maxBytes = 1_000_000
    /// File bytes in one part (the rest of the 64 KB frame is header, seal and part number).
    static let partBytes = 58_000

    var text: String { "📎 " + name }

    /// A name that fits, keeping its extension: "A very long report name….pdf".
    static func fit(_ name: String) -> String {
        guard name.utf8.count > maxName else { return name }
        let ext = (name as NSString).pathExtension
        let tail = ext.isEmpty || ext.utf8.count > 8 ? "" : "." + ext
        var base = Substring((name as NSString).deletingPathExtension)
        while base.utf8.count + tail.utf8.count + 3 > maxName, !base.isEmpty { base = base.dropLast() }
        return base + "…" + tail
    }
}

/// A chat's three tabs, and the way a message in each goes: SMS only; internet and phones nearby ("Data"); the
/// Meshtastic radio ("Mesh"). A message carries its lane (extra 16), so it shows in the same tab on every phone
/// whichever way it arrived.
enum Lane: String, Codable, CaseIterable, Identifiable {
    /// In this order on screen, as the networks on the chats page. Nearby (phones nearby, 19 Nov) was part of Data before: older versions show its
    /// messages (code 3, unknown to them) by the way they came.
    case sms, data, nearby, mesh
    var id: String { rawValue }
    var code: UInt8 { switch self { case .data: 0; case .sms: 1; case .mesh: 2; case .nearby: 3 } }
    init?(code: UInt8) { switch code { case 0: self = .data; case 1: self = .sms; case 2: self = .mesh; case 3: self = .nearby; default: return nil } }
    /// Photos, files and voice messages: the internet and phones nearby only (too big for the radio and SMS).
    var big: Bool { self == .data || self == .nearby }
}

/// What's inside a frame.
struct Note: Equatable {
    var sender: UInt32
    var name: String
    var text: String
    var sent: Date
    var place: Place?
    var photo: PhotoRef?
    var file: FileRef?
    /// A delivery confirmation: ids of messages this phone has received (no text; not shown as a message).
    var receipts: [UInt64] = []
    /// Something for the chat's map: where I am, how I am, a pin, or a pin taken off.
    var mark: Mark?
    /// "I've joined the chat", sent once by a phone that joins.
    var joined = false
    /// The sender's phone number (Settings), so the others can text them: when they join, when it changes, and
    /// to someone who just joined.
    var number: String?

    static let maxNumber = 20
    /// An emoji on someone's message (empty: taken off). Not a message itself.
    var reaction: Reaction?
    /// A reply to this message (its id).
    var replyTo: UInt64?
    /// New text for one of my messages (its id): not a message itself.
    var edits: UInt64?
    /// One of my messages, deleted for everyone (its id): not a message itself.
    var deletes: UInt64?
    /// Passed on from another chat.
    var forwarded = false
    /// "I've left the chat" (extra 17), the last thing a phone sends to a chat it deletes: the others see "… left" and
    /// take them off their list of people.
    var left = false
    /// The sender's colour (0–6, Settings → Appearance), for their name and their dot on the map. Sent with their number.
    var colour: UInt8?
    /// A map area to save for offline use.
    var area: MapArea?
    /// The whole map at once (extra 23, maybe several): every pin and everyone's last place, for someone only SMS reaches.
    var snapshot: MapSnapshot?
    /// With a confirmation: of those messages, the ones this phone got by SMS and passed on to the chat, so the
    /// others show who shared them (extra 15).
    var carried: [UInt64] = []
    /// The tab it was written in, so the way it was sent (extra 16).
    var lane: Lane?
    /// With a location sent (📍 My Location): the networks the sender could use right then, so the others know how to
    /// reach them (extra 18; `Reach`).
    var reach: Reach?
    /// The sender's identity key (extra 19): P-256, 64 bytes, so the chat's creator can hand them a new chat key that
    /// only they can open (Rekey). Sent with their number, and when they join.
    var identity: Data?
    /// With the identity: "I made this chat" (extra 20). Only its maker can take someone out of it.
    var owner = false
    /// The chat's maker took someone out (extra 21): the chat's new key, for each who stays, that only they can open.
    var rekey: Rekey?
    /// "Don't use my number in this chat any more" (extra 22): I stopped sharing it here (the chat's info).
    var noNumber = false

    /// How many messages one confirmation covers.
    static let maxReceipts = 8

    static let maxName = 20
    /// An identity key's size (extra 19): P-256, X and Y, 32 bytes each.
    static let identitySize = 64
    /// Keeps the whole frame inside one radio packet.
    static let maxText = 140

    var packed: Data {
        var w = Bytes()
        w.u8(1)
        w.u32(sender)
        w.u32(UInt32(sent.timeIntervalSince1970))
        w.text(name, max: Self.maxName)
        w.text(text, max: Self.maxText)
        // Extras after the text, each a type and length byte (older versions stop reading at the text).
        if let p = place {
            w.u8(1); w.u8(10)
            w.u32(UInt32(bitPattern: Int32(clamping: Int((p.latitude * 1e7).rounded()))))
            w.u32(UInt32(bitPattern: Int32(clamping: Int((p.longitude * 1e7).rounded()))))
            w.u16(UInt16(clamping: max(0, p.accuracy)))
        }
        if let p = photo, let id = UInt64(p.id, radix: 16) {
            w.u8(2); w.u8(16)
            w.u64(id)
            w.u32(UInt32(clamping: max(0, p.bytes)))
            w.u16(UInt16(clamping: max(0, p.width)))
            w.u16(UInt16(clamping: max(0, p.height)))
        }
        if let f = file, let id = UInt64(f.id, radix: 16) {
            var e = Bytes()
            e.u64(id)
            e.u32(UInt32(clamping: max(0, f.bytes)))
            e.u16(UInt16(clamping: max(0, f.parts)))
            e.text(f.name, max: FileRef.maxName)
            w.u8(3); w.u8(UInt8(e.data.count))
            w.data.append(e.data)
        }
        if !receipts.isEmpty {
            let ids = receipts.prefix(Self.maxReceipts)
            w.u8(4); w.u8(UInt8(1 + 8 * ids.count))
            w.u8(UInt8(ids.count))
            for id in ids { w.u64(id) }
        }
        if let m = mark {
            var e = Bytes()
            e.u8(m.kind.rawValue)
            e.u32(m.id)
            e.u32(UInt32(bitPattern: Int32(clamping: Int((m.latitude * 1e7).rounded()))))
            e.u32(UInt32(bitPattern: Int32(clamping: Int((m.longitude * 1e7).rounded()))))
            e.u16(UInt16(clamping: max(0, m.accuracy)))
            e.text(m.label, max: Mark.maxLabel)
            w.u8(5); w.u8(UInt8(e.data.count))
            w.data.append(e.data)
        }
        if joined { w.u8(6); w.u8(0) }
        if let n = number, !n.isEmpty {
            var e = Bytes()
            e.text(n, max: Self.maxNumber)
            w.u8(7); w.u8(UInt8(e.data.count))
            w.data.append(e.data)
        }
        if let r = reaction {
            var e = Bytes()
            e.u64(r.to)
            e.text(r.emoji, max: Reaction.maxEmoji)
            w.u8(8); w.u8(UInt8(e.data.count))
            w.data.append(e.data)
        }
        for (type, id) in [(UInt8(9), replyTo), (10, edits), (11, deletes)] {
            guard let id else { continue }
            w.u8(type); w.u8(8); w.u64(id)
        }
        if forwarded { w.u8(12); w.u8(0) }
        if let c = colour { w.u8(13); w.u8(1); w.u8(c) }
        if let a = area {
            w.u8(14); w.u8(17)
            for v in [a.south, a.west, a.north, a.east] { w.u32(UInt32(bitPattern: Int32(clamping: Int((v * 1e7).rounded())))) }
            w.u8(UInt8(clamping: a.maxZoom))
        }
        if !carried.isEmpty {
            let ids = carried.prefix(Self.maxReceipts)
            w.u8(15); w.u8(UInt8(1 + 8 * ids.count))
            w.u8(UInt8(ids.count))
            for id in ids { w.u64(id) }
        }
        if let l = lane { w.u8(16); w.u8(1); w.u8(l.code) }
        if left { w.u8(17); w.u8(0) }
        if let r = reach { w.u8(18); w.u8(1); w.u8(r.rawValue) }
        if let i = identity, i.count == Note.identitySize { w.u8(19); w.u8(UInt8(i.count)); w.data.append(i) }
        if owner { w.u8(20); w.u8(0) }
        if noNumber { w.u8(22); w.u8(0) }
        for chunk in snapshot?.chunks ?? [] { w.u8(23); w.u8(UInt8(chunk.count)); w.data.append(chunk) }
        if let k = rekey {
            var e = Bytes()
            e.u32(k.removed)
            for (id, sealed) in k.keys.prefix(Rekey.perNote) where sealed.count == Rekey.sealedSize { e.u32(id); e.data.append(sealed) }
            w.u8(21); w.u8(UInt8(e.data.count))
            w.data.append(e.data)
        }
        return w.data
    }

    init(sender: UInt32, name: String, text: String, sent: Date = .nowInSeconds, place: Place? = nil, photo: PhotoRef? = nil, file: FileRef? = nil) {
        self.sender = sender; self.name = name; self.text = text; self.sent = sent; self.place = place; self.photo = photo; self.file = file
    }

    init?(packed: Data) {
        var r = Bytes(packed)
        guard r.u8() == 1, let sender = r.u32(), let sent = r.u32(), let name = r.text(), let text = r.text() else { return nil }
        self.sender = sender
        self.sent = Date(timeIntervalSince1970: TimeInterval(sent))
        self.name = name
        self.text = text
        while let type = r.u8(), let n = r.u8(), let v = r.take(Int(n)) {
            var e = Bytes(v)
            switch type {
            case 1:
                if let lat = e.u32(), let lon = e.u32(), let acc = e.u16() {
                    place = Place(latitude: Double(Int32(bitPattern: lat)) / 1e7, longitude: Double(Int32(bitPattern: lon)) / 1e7, accuracy: Int(acc))
                }
            case 2:
                if let id = e.u64(), let bytes = e.u32(), let w = e.u16(), let h = e.u16() {
                    photo = PhotoRef(id: id.hexID, bytes: Int(bytes), width: Int(w), height: Int(h))
                }
            case 3:
                if let id = e.u64(), let bytes = e.u32(), let parts = e.u16(), let name = e.text() {
                    file = FileRef(id: id.hexID, name: name, bytes: Int(bytes), parts: Int(parts))
                }
            case 4:
                if let n = e.u8() { receipts = (0..<Int(n)).compactMap { _ in e.u64() } }
            case 5:
                if let k = e.u8(), let kind = Mark.Kind(rawValue: k), let id = e.u32(), let lat = e.u32(), let lon = e.u32(),
                   let acc = e.u16() {
                    mark = Mark(kind: kind, id: id, latitude: Double(Int32(bitPattern: lat)) / 1e7,
                                longitude: Double(Int32(bitPattern: lon)) / 1e7, accuracy: Int(acc), label: e.text() ?? "")
                }
            case 6:
                joined = true
            case 7:
                number = e.text().flatMap { $0.isEmpty ? nil : $0 }
            case 8:
                if let to = e.u64(), let emoji = e.text() { reaction = Reaction(to: to, emoji: emoji) }
            case 9: replyTo = e.u64()
            case 10: edits = e.u64()
            case 11: deletes = e.u64()
            case 12: forwarded = true
            case 13: colour = e.u8().flatMap { $0 < 7 ? $0 : nil }
            case 14:
                if let s = e.u32(), let w = e.u32(), let n = e.u32(), let ea = e.u32(), let z = e.u8() {
                    func d(_ v: UInt32) -> Double { Double(Int32(bitPattern: v)) / 1e7 }
                    area = MapArea(south: d(s), west: d(w), north: d(n), east: d(ea), maxZoom: Int(z))
                }
            case 15:
                if let n = e.u8() { carried = (0..<Int(n)).compactMap { _ in e.u64() } }
            case 16: lane = e.u8().flatMap(Lane.init(code:))
            case 17: left = true
            case 18: reach = e.u8().map { Reach(rawValue: $0) }
            case 19: if v.count == Note.identitySize { identity = v }
            case 20: owner = true
            case 22: noNumber = true
            case 23:
                var snap = snapshot ?? MapSnapshot()
                snap.read(v)
                snapshot = snap
            case 21:
                if let removed = e.u32() {
                    var keys: [(UInt32, Data)] = []
                    while let id = e.u32(), let sealed = e.take(Rekey.sealedSize) { keys.append((id, sealed)) }
                    rekey = Rekey(removed: removed, keys: keys)
                }
            default: break
            }
        }
    }

    /// Cuts text to whole characters that fit in a message.
    static func fit(_ s: String) -> String {
        var cut = Substring(s)
        while cut.utf8.count > maxText { cut = cut.dropLast() }
        return String(cut)
    }
}

/// The networks someone could use when they sent where they are (extra 18): SMS, the internet, phones nearby, the radio.
struct Reach: OptionSet, Codable, Hashable {
    let rawValue: UInt8
    static let sms = Reach(rawValue: 1)
    static let internet = Reach(rawValue: 2)
    static let nearby = Reach(rawValue: 4)
    static let radio = Reach(rawValue: 8)
}

/// The chat's maker took `removed` out of the chat (extra 21): 4 bytes them, then for each person who stays (and for
/// the one removed: 32 zero bytes, so they know it's really the maker) 4 bytes their id and the new chat key sealed
/// for them alone (AES-GCM, 60 bytes) with a key only the maker and they can work out (Identity). Two a note: one radio packet.
struct Rekey: Equatable {
    var removed: UInt32
    var keys: [(UInt32, Data)]

    static let sealedSize = 60
    static let perNote = 2

    static func == (a: Rekey, b: Rekey) -> Bool {
        a.removed == b.removed && a.keys.map(\.0) == b.keys.map(\.0) && a.keys.map(\.1) == b.keys.map(\.1)
    }
}

/// An emoji on a message (extra 8): 8 bytes the message's id, then the emoji as a short text (empty: taken off).
struct Reaction: Equatable {
    var to: UInt64
    var emoji: String

    static let maxEmoji = 16
    /// The ones offered.
    static let choices = ["👍", "❤️", "😂", "😮", "😢", "🙏"]
}

/// A chat's whole map in one message (extra 23), so someone only SMS reaches catches up on what changed on Data:
/// every pin, the pins taken off lately, and everyone's last place and status. Items one after another, each starting
/// with its type: 1 pin (kind, id, latitude, longitude, who put it, label), 2 person (id, latitude, longitude,
/// minutes before the message, status or 0, name), 3 pin taken off (id). Split over extras of at most 255 bytes.
/// The same bytes as the Android app's MapSnapshot.
struct MapSnapshot: Equatable {
    struct Pin: Equatable {
        var kind: Mark.Kind
        var id: UInt32
        var latitude: Double
        var longitude: Double
        var sender: UInt32
        var label: String
    }

    struct Person: Equatable {
        var id: UInt32
        var latitude: Double
        var longitude: Double
        var minutesAgo: Int
        var status: Mark.Kind?
        var name: String
    }

    var pins: [Pin] = []
    var people: [Person] = []
    var removed: [UInt32] = []

    static let maxPins = 30
    static let maxRemoved = 10
    static let maxLabel = 16
    static let maxName = 12

    var isEmpty: Bool { pins.isEmpty && people.isEmpty && removed.isEmpty }

    private static func coord(_ w: inout Bytes, _ v: Double) { w.u32(UInt32(bitPattern: Int32(clamping: Int((v * 1e7).rounded())))) }
    private static func coord(_ r: inout Bytes) -> Double? { r.u32().map { Double(Int32(bitPattern: $0)) / 1e7 } }

    /// Each item's bytes, packed into extras of at most 255 bytes.
    var chunks: [Data] {
        var items: [Data] = []
        for p in pins {
            var w = Bytes()
            w.u8(1); w.u8(p.kind.rawValue); w.u32(p.id)
            Self.coord(&w, p.latitude); Self.coord(&w, p.longitude)
            w.u32(p.sender); w.text(p.label, max: Self.maxLabel)
            items.append(w.data)
        }
        for p in people {
            var w = Bytes()
            w.u8(2); w.u32(p.id)
            Self.coord(&w, p.latitude); Self.coord(&w, p.longitude)
            w.u16(UInt16(clamping: max(0, p.minutesAgo))); w.u8(p.status?.rawValue ?? 0)
            w.text(p.name, max: Self.maxName)
            items.append(w.data)
        }
        for id in removed {
            var w = Bytes()
            w.u8(3); w.u32(id)
            items.append(w.data)
        }
        var out: [Data] = [], cur = Data()
        for i in items {
            if cur.count + i.count > 255 { out.append(cur); cur = Data() }
            cur.append(i)
        }
        if !cur.isEmpty { out.append(cur) }
        return out
    }

    /// Adds the items in one extra.
    mutating func read(_ chunk: Data) {
        var r = Bytes(chunk)
        while let type = r.u8() {
            switch type {
            case 1:
                guard let k = r.u8(), let id = r.u32(), let lat = Self.coord(&r), let lon = Self.coord(&r), let by = r.u32(),
                      let label = r.text() else { return }
                if let kind = Mark.Kind(rawValue: k), kind.rawValue >= 10 {
                    pins.append(Pin(kind: kind, id: id, latitude: lat, longitude: lon, sender: by, label: label))
                }
            case 2:
                guard let id = r.u32(), let lat = Self.coord(&r), let lon = Self.coord(&r), let ago = r.u16(), let st = r.u8(),
                      let name = r.text() else { return }
                let status = Mark.Kind(rawValue: st).flatMap { [.ok, .danger, .help].contains($0) ? $0 : nil }
                people.append(Person(id: id, latitude: lat, longitude: lon, minutesAgo: Int(ago), status: status, name: name))
            case 3:
                guard let id = r.u32() else { return }
                removed.append(id)
            default:
                return
            }
        }
    }
}

/// Something on a chat's map, carried in a message (extra 5): 1 kind, 4 id, 4+4 latitude/longitude (1e-7°),
/// 2 accuracy (m; 65535: unknown), then a short label. The same bytes as the Android app's Mark.
struct Mark: Codable, Equatable {
    enum Kind: UInt8, Codable, CaseIterable {
        /// Takes pin `id` off the map; id 0: I stopped sharing where I am.
        case remove = 0
        /// Where I am, while I share it (not shown as a message).
        case position = 1
        /// How I am, at my position: OK, in danger, need help.
        case ok = 2, danger = 3, help = 4
        /// Pins anyone puts on the map.
        case hazard = 10, shelter = 11, water = 12, medical = 13, meetingPoint = 14, pin = 15
        /// Themes' pins (ChatTheme): festival 20…, airsoft / paintball 30…, conference 40…
        case stage = 20, toilets = 21, bar = 22, food = 23, tent = 24, entrance = 25
        case base = 30, objective = 31, enemy = 32, ally = 33, sniper = 34, respawn = 35, safeZone = 36
        case room = 40, registration = 41, coffee = 42, talk = 43, lunch = 44, booth = 45, wifi = 46
    }

    var kind: Kind
    /// A pin's own number (random), so it can be taken off; 0 for my position and status.
    var id: UInt32 = 0
    var latitude: Double
    var longitude: Double
    var accuracy: Int = 0
    var label: String = ""

    static let maxLabel = 40
    /// With kind remove: id 0 stops my live location, id 1 takes my status (OK / Danger / Help) off; other ids are pins.
    static let stopSharingID: UInt32 = 0
    static let clearStatusID: UInt32 = 1
    static let unknown = 65_535

    /// No position with it (a status sent before the phone knew where it was).
    var hasPlace: Bool { accuracy != Self.unknown && !(latitude == 0 && longitude == 0) }
    /// Shown as a message in the chat (a status or a pin), or only on the map.
    var isShown: Bool { kind != .remove && kind != .position }
    var isStatus: Bool { kind == .ok || kind == .danger || kind == .help }
    var isPin: Bool { kind.rawValue >= 10 }
}

/// A chat's secret: 32 random bytes, shared by QR code or invite link. Everything else is worked out from it.
struct ChatKey: Equatable {
    let raw: Data

    static func random() -> ChatKey {
        ChatKey(raw: SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })!
    }

    init?(raw: Data) {
        guard raw.count == 32 else { return nil }
        self.raw = raw
    }

    private func derive(_ label: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: raw), info: Data("arke.\(label)".utf8), outputByteCount: 32)
    }

    private var sealKey: SymmetricKey { derive("seal") }

    var room: Data { derive("room").withUnsafeBytes { Data($0.prefix(8)) } }

    /// The internet relay's topic: says nothing about the key, and only people with the key can work it out.
    var topic: String { "arke-" + topicBytes.hex }
    var topicBytes: Data { derive("topic").withUnsafeBytes { Data($0.prefix(12)) } }

    /// Shown so people can check they have the same chat: same code, same key.
    var safetyCode: String {
        let h = derive("check").withUnsafeBytes { Data($0.prefix(4)) }
        let n = h.reduce(UInt32(0)) { $0 << 8 | UInt32($1) } % 1_000_000
        return String(format: "%03d %03d", n / 1000, n % 1000)
    }

    func seal(_ note: Note, id: UInt64 = .random(in: 1...UInt64.max), expires: Date? = nil) throws -> Frame {
        var f = Frame(room: room, id: id, expires: expires ?? note.sent.addingTimeInterval(Frame.lifetime), sealed: Data())
        f.sealed = try AES.GCM.seal(note.packed, using: sealKey, authenticating: f.header).combined!
        return f
    }

    /// A photo's JPEG bytes, sealed as a frame of its own.
    func sealPhoto(_ jpeg: Data, id: UInt64, sent: Date = .nowInSeconds) throws -> Frame {
        var f = Frame(room: room, id: id, expires: sent.addingTimeInterval(Frame.lifetime), sealed: Data(), version: Frame.photo)
        f.sealed = try AES.GCM.seal(jpeg, using: sealKey, authenticating: f.header).combined!
        return f
    }

    /// One part of a file: its number, how many there are, and its bytes, sealed as a frame of its own (id: the file's + `index`).
    func sealFilePart(_ bytes: Data, index: Int, count: Int, file id: UInt64, sent: Date = .nowInSeconds) throws -> Frame {
        var f = Frame(room: room, id: id &+ UInt64(index), expires: sent.addingTimeInterval(Frame.lifetime), sealed: Data(), version: Frame.filePart)
        var w = Bytes()
        w.u16(UInt16(index))
        w.u16(UInt16(count))
        w.data.append(bytes)
        f.sealed = try AES.GCM.seal(w.data, using: sealKey, authenticating: f.header).combined!
        return f
    }

    func openFilePart(_ f: Frame) -> (file: UInt64, index: Int, count: Int, bytes: Data)? {
        guard f.isFilePart, f.room == room, let box = try? AES.GCM.SealedBox(combined: f.sealed),
              let d = try? AES.GCM.open(box, using: sealKey, authenticating: f.header) else { return nil }
        var r = Bytes(d)
        guard let i = r.u16(), let n = r.u16(), i < n else { return nil }
        return (f.id &- UInt64(i), Int(i), Int(n), r.rest)
    }

    func openPhoto(_ f: Frame) -> Data? {
        guard f.isPhoto, f.room == room, let box = try? AES.GCM.SealedBox(combined: f.sealed) else { return nil }
        return try? AES.GCM.open(box, using: sealKey, authenticating: f.header)
    }

    func open(_ f: Frame) -> Note? {
        guard !f.isBig, f.room == room, let box = try? AES.GCM.SealedBox(combined: f.sealed),
              let data = try? AES.GCM.open(box, using: sealKey, authenticating: f.header) else { return nil }
        return Note(packed: data)
    }
}

extension UInt64 {
    /// A frame or message id as text (hex).
    var hexID: String { String(self, radix: 16) }
}

extension Date {
    /// Whole seconds, as messages carry them.
    static var nowInSeconds: Date { Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)) }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URL s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        self.init(base64Encoded: b)
    }
}

/// Little-endian bytes in and out, for the compact message format.
struct Bytes {
    var data = Data()
    private var at = 0

    init() {}
    init(_ data: Data) { self.data = Data(data) }

    mutating func u8(_ v: UInt8) { data.append(v) }
    mutating func u16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
    mutating func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
    mutating func u64(_ v: UInt64) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }

    /// Text cut to whole characters that fit in `max` bytes.
    mutating func text(_ s: String, max: Int) {
        var cut = Substring(s)
        while cut.utf8.count > max { cut = cut.dropLast() }
        u8(UInt8(cut.utf8.count))
        data.append(contentsOf: cut.utf8)
    }

    mutating func take(_ n: Int) -> Data? {
        guard at + n <= data.count else { return nil }
        defer { at += n }
        return data.subdata(in: at..<at + n)
    }

    mutating func u8() -> UInt8? { take(1)?.first }
    mutating func u16() -> UInt16? { take(2).map { UInt16($0[0]) | UInt16($0[1]) << 8 } }
    mutating func u32() -> UInt32? { take(4).map { $0.reversed().reduce(0) { $0 << 8 | UInt32($1) } } }
    mutating func u64() -> UInt64? { take(8).map { $0.reversed().reduce(0) { $0 << 8 | UInt64($1) } } }

    mutating func text() -> String? {
        guard let n = u8(), let b = take(Int(n)) else { return nil }
        return String(decoding: b, as: UTF8.self)
    }

    var rest: Data { at < data.count ? data.subdata(in: at..<data.count) : Data() }
}
