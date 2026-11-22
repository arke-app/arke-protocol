# Arke protocol

[Arke](https://arke-app.github.io/) is an encrypted group chat that works over SMS, the internet, phones nearby and
Meshtastic radios. This repository is the part that keeps your messages private, in the open, so anyone can check it:

- **[PROTOCOL.md](PROTOCOL.md)** — how a chat key, a message and every network work, byte by byte, with test vectors,
  and an honest list of what Arke protects and what it doesn't.
- **`swift/`** — the iPhone app's `Frame.swift` (keys, sealing, the message format) and `Identity.swift` (removing
  someone from a chat).
- **`kotlin/`** — the Android app's `Frame.kt` and `Identity.kt`. Both apps write exactly the same bytes.

The code here is copied from the apps as they are released (it isn't a separate library), so what you read is what
runs on the phones. The rest of the apps (screens, maps, purchases) isn't published.

What it uses: AES-256-GCM, HKDF-SHA256, P-256 ECDH — Apple CryptoKit on iPhone, the Java standard library on Android.
No accounts, no phone-number sign-up, no analytics. The internet relay is [ntfy](https://github.com/binwiederhier/ntfy)
(open source); you can run your own.

Found a problem? Please write to the contact on the [Arke site](https://arke-app.github.io/) before publishing it, so it can be fixed first.

MIT licence.
