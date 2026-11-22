# The Arke protocol

How Arke seals and carries messages, byte by byte. The iPhone app (`swift/`) and the Android app (`kotlin/`) write
exactly the same bytes; the test vectors below are checked by both apps' tests.

All numbers are little-endian. "text" is one length byte then UTF-8, cut at whole characters.

## 1. The chat key

A chat is a 32-byte random key. Everything else comes from it with HKDF-SHA256 (no salt, 32 bytes out), with the
info string `"arke." + label`:

| Label | Used for |
|---|---|
| `seal` | the AES-256-GCM key that seals every message |
| `room` | first 8 bytes: the room tag in every frame, so a phone finds its own chats' messages without trying every key |
| `topic` | first 12 bytes, in hex, after `arke-`: the internet relay topic |
| `check` | first 4 bytes, as a big-endian number mod 1 000 000: the 6-digit safety code people compare |

The key is shared only in the invite: a QR code shown face to face, or a link
`https://arke-app.github.io/join/#k=<key base64url>&n=<name>[&r=…][&s=…][&o=…][&t=…]`. Everything after `#` stays on
the phone: browsers never send it to the website.

Invite fields: `k` key, `n` chat name, `r` radio channel, `s` relay server (only when not the default), `o` the
maker's identity key, `t` the chat's theme (`f` festival, `a` airsoft / paintball, `c` conference).

## 2. Frames

Every message, on every network (SMS link, internet relay, phones nearby, Meshtastic radio), is one frame:

```
"MC" (2) | version (1) | room tag (8) | id (8) | expires (4, seconds since 1970) | sealed
```

`sealed` is AES-GCM `nonce (12) | ciphertext | tag (16)` with the `seal` key, and the header (everything before
`sealed`) as additional authenticated data, so no carrier can change the header unnoticed.

| Version | Contents |
|---|---|
| 1 | a Note (below). At most 233 bytes, so it fits one Meshtastic packet; text at most 140 bytes |
| 2 | a photo: sealed JPEG bytes (up to 64 KB). Internet and phones nearby only |
| 3 | a file part: `index (2) | count (2) | bytes`; the frame id is the file id + index. Internet and phones nearby only |
| 4 | a **post** (the bridge, 1.1): not sealed by Arke itself — `relay topic (12) | a whole frame`, with id = that frame's id XOR `0x5A5A5A5A5A5A5A5A`. A phone without the internet hands it to a phone nearby, which puts the inner frame on the relay. The phone passing it on can't open the inner frame |

Frames live 48 hours. Any Arke phone carries frames for any chat; only phones with the key open them.

## 3. Notes (version 1, inside the seal)

```
1 (1) | sender id (4) | sent (4, seconds) | name (text, ≤ 20 bytes) | text (text, ≤ 140 bytes) | extras…
```

Each extra is `type (1) | length (1) | value`. Older versions stop reading at the text, so new extras never break
them.

| Type | Value |
|---|---|
| 1 | place: latitude, longitude (i32 × 1e7), accuracy m (u16) |
| 2 | photo: id (8), bytes (4), width (2), height (2) |
| 3 | file: id (8), bytes (4), parts (2), name (text) |
| 4 | delivered: count (1), ids (8 each, up to 8) |
| 5 | map mark: kind (1), id (4), latitude, longitude (i32 × 1e7), accuracy (u16; 65535 unknown), label (text ≤ 40) |
| 6 | joined (empty) |
| 7 | phone number (text) |
| 8 | reaction: message id (8), emoji (text; empty takes it off) |
| 9, 10, 11 | reply to / edits / deletes: message id (8) |
| 12 | forwarded (empty) |
| 13 | colour 0–6 (1) |
| 14 | map area: south, west, north, east (i32 × 1e7), deepest zoom (1) |
| 15 | shared by: message ids passed on from SMS (count, 8 each) |
| 16 | tab: 0 Data, 1 SMS, 2 Mesh, 3 Nearby |
| 17 | left the chat (empty) |
| 18 | networks the sender could use (bits: 1 SMS, 2 internet, 4 nearby, 8 radio) |
| 19 | identity key: P-256 public key, 64 bytes |
| 20 | "I made this chat" (empty) |
| 21 | new chat key after someone was removed (section 5) |
| 22 | "don't use my number here any more" (empty) |
| 23 | whole map (1.1): items, each `1` pin (kind, id, lat, lon, who put it, label ≤ 16) · `2` person (id, lat, lon, minutes ago (2), status, name ≤ 12) · `3` pin removed (id). Repeated extras of ≤ 255 bytes |

Map mark kinds: 0 remove, 1 position, 2 OK, 3 danger, 4 help, 10–15 emergency pins, 20–25 festival, 30–36 airsoft /
paintball, 40–46 conference.

## 4. The networks

- **SMS**: the frame as a link, `https://arke-app.github.io/m/#<frames base64url>`, sent by the user's own messages
  app. A link only opens on a phone that has the chat's key.
- **Internet**: the frame (base64url) posted to an [ntfy](https://ntfy.sh) server, on the chat's topic. Arke's
  default server is `arke.relay.needtoapp.com`; anyone can use their own ntfy server instead.
- **Phones nearby**: iPhone ↔ iPhone over Multipeer Connectivity; anything ↔ Android over Bluetooth LE. Phones swap
  the ids they have, then only what's missing.
- **Meshtastic radio**: the frame as one packet on Arke's own channel (key: the first 16 bytes of
  SHA-256("arke.channel"), the same on every Arke phone — the radio channel is not the secret, the chat key is).

## 5. Removing someone

Each phone has a P-256 identity key (extra 19). When the chat's maker removes someone, it makes a new chat key and,
for each person who stays, seals it with AES-GCM under a key from ECDH(maker, that person) → HKDF-SHA256 (salt: the
old room tag, info: `"arke.rekey"` + the person's id, big-endian). The removed person gets zeros. Extra 21 is
`removed id (4)` then `(person id (4), sealed (60))` pairs.

## 6. What this protects, and what it doesn't

Protected:
- What is said, who says it (name and sender id), where people are, photos, files, voice: only phones with the chat
  key can read them. The relay server, phones that carry frames, the radio and the phone network see sealed bytes.
- A carrier can't change a frame: the header is authenticated.

Not protected (stated honestly):
- **Who is in a chat is decided by the key.** Anyone who gets the invite (the link or the QR code) is in the chat.
  Share it only with people you know.
- **Members are not authenticated to each other.** Everyone in a chat has the same key, so a member could write as
  if they were someone else in that chat. The safety code only shows that two phones have the same key.
- **No forward secrecy.** The chat key doesn't change by itself; someone who records frames and later gets the key
  can read them. Removing someone makes a new key.
- **Metadata.** Whoever sees frames sees their size, time, expiry and room tag; the relay server sees its topic, when
  it's used, and the IP address that posts or reads. Frames of the same chat share the same room tag and topic.
- **The phones themselves.** A phone that's unlocked, or has malware, can read what's on it.

## Test vectors

Built by `swift/Frame.swift` and checked by the Android app's tests (`FrameTest`).

**Note with a status mark and "joined"** — sender `0x01020304`, name "Ana", text "🆘 I need help", sent 1700000000,
mark: help, id `0xA1B2C3D4`, 38.72231, −9.13934, accuracy 12, label "Ponte":

```
010403020100f1536503416e6110f09f86982049206e6565642068656c70051504d4c3b2a13c8e141788728dfa0c0005506f6e74650600
```

**Note with a whole map (extra 23)** — sender `0xA1B2C3D4`, name "Ana", text "🗺 map", sent 1800000000; pins
(shelter, `0xDEADBEEF`, 38.7262, −9.1451, by 7, "Escola") and (meeting point, 42, −1.5, 2.25, by `0xFFFFFFFF`, "");
people (`0x01020304`, 38.7171, −9.1318, 75 min, help, "Rui Silva") and (9, 0.1, −0.1, 0 min, none, "Zé"); removed
5 and `0x80000000`:

```
01d4c3b2a100d2496b03416e6108f09f97ba206d61701764010befbeadde3026151788918cfa07000000064573636f6c61010e2a000000401e1bffa0525701ffffffff000204030201b8c2131710998efa4b0004095275692053696c7661020900000040420f00c0bdf0ff000000035ac3a903050000000300000080
```

**Post frame (version 4)** — inner frame: room 01…08, id `0x0123456789ABCDEF`, expires 1800000000, sealed bytes
`i × 3` for i in 0..<40; topic bytes 200…211:

```
4d43040102030405060708b597f1d33d1f795b00d2496bc8c9cacbcccdcecfd0d1d2d34d43010102030405060708efcdab896745230100d2496b000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275
```
