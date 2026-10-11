# Live location sharing: design

Status: **approved for implementation**, after three review rounds:

- 2026-10-10: D1–D14 approved with a list of fixes, which §16 maps to their changes.
- 2026-10-11: D15–D17 approved; the requested changes are mapped in §17.
- 2026-10-11: D18 approved; the requested changes are mapped in §18.

All decisions are made ([§14](#14-decisions)). No feature code has been written yet.

The normative protocol is in [LIVE_LOCATION_PROTOCOL.md](LIVE_LOCATION_PROTOCOL.md) ("NLL v1"). The
reference implementation, test vectors and the relay test harness are in
[`tools/python/live_location/`](../tools/python/live_location/).

## Contents

0. [Summary](#0-summary)
1. [Phase 0 report](#1-phase-0-report)
2. [Requirements traceability](#2-requirements-traceability)
3. [Threat model](#3-threat-model)
4. [Protocol overview](#4-protocol-overview)
5. [Cryptographic construction and rationale](#5-cryptographic-construction-and-rationale)
6. [Transport evaluation and relay test results](#6-transport-evaluation-and-relay-test-results)
7. [Fan-out: 1, 10 and 50 recipients](#7-fan-out-1-10-and-50-recipients)
8. [Architecture and code placement](#8-architecture-and-code-placement)
9. [Dependencies](#9-dependencies)
10. [Android specifics: location, power, data, key storage](#10-android-specifics-location-power-data-key-storage)
11. [UX flows](#11-ux-flows)
12. [Test plan](#12-test-plan)
13. [Risks](#13-risks)
14. [Decisions](#14-decisions)
15. [Answers to the Phase 1 questions](#15-answers-to-the-phase-1-questions)
16. [Review changes (2026-10-10)](#16-review-changes-2026-10-10)
17. [Second review changes (2026-10-11)](#17-second-review-changes-2026-10-11)
18. [Third review changes (2026-10-11)](#18-third-review-changes-2026-10-11)

## 0. Summary

- **What.** You pair with someone once, in person by QR code or remotely by link. From then on
  either of you can share your live location with any set of paired contacts, for a fixed time or
  until stopped. Anyone sharing with you appears on your map as a named dot that follows them.
- **Transport.** Ordinary public Nostr relays (or your own), used as dumb, untrusted, interchangeable
  pipes. Every event goes to all of a user's relays (default: three), so any single relay, or any two
  of three, can fail.
- **Privacy.** Relays never see positions, names or any long-lived identifier.
  - There are **no identity keys at all**. Every event is signed by a pseudonymous key: per invite,
    per contact-direction per day, or per share stream.
  - Every payload of a class is padded to the same size.
  - What relays do see is network metadata: IP addresses, timing, volume, and which keys one
    connection uses within a day. From that, a relay can work out which phones (by IP address)
    follow a share. [§3](#3-threat-model) lists what each party can learn.
- **Retention.** Relays that follow the protocol hold only the *latest* position of an active share
  (an addressable event). It expires 15 minutes after publication, or sooner when the share ends.
  Viewers keep each contact's latest position in memory only. Anyone can copy the encrypted events;
  what protects such copies is that both ends erase their keys within about a day (§5).
- **Revocation.** Each share uses a random stream key. Removing a recipient (or its time limit
  passing) starts a new stream that only the remaining recipients are told about. The removed
  person cannot decrypt anything after that. What it receives looks exactly like you stopping
  altogether; at most, it can guess from traffic timing that a new stream started on your relays
  (T4).
- **Crypto.** Only standard parts are used: a hash commitment plus Noise `NNpsk0` for pairing;
  HKDF-SHA256 chains, ratcheted daily for forward secrecy; NIP-44 v2 for payloads; BIP-340 Schnorr for Nostr events.
  Every primitive is checked against its published vectors (200 checks pass), and the protocol has
  its own deterministic test vectors.
- **Evidence.**
  - Phase 0 is done: the unmodified fdroidDebug arm64 APK builds, and the existing desktop tests run.
  - 20 public relays were probed, plus a 30-minute soak test ([§6](#6-transport-evaluation-and-relay-test-results)).
  - Mainstream relays accept this traffic with no account, PoW or payment.
  - Over 30 minutes at one update per 5 s: no refusals, p50 about 250 ms, and p99 ≤ 374 ms on the
    recommended relays.
  - Idle connections: two of the three default relays send a keep-alive ping every 240 s, the third
    every 55 s. This shapes the battery policy (§10.3).
- **Needs you.** Nothing for the design: D1–D18 are signed off ([§14](#14-decisions)). Device
  testing will be yours, because this environment cannot run an emulator.

## 1. Phase 0 report

| Item | Result |
|---|---|
| Machine | Ubuntu 24.04 container, 4 cores, 15 GB RAM, **no `/dev/kvm`** → no Android emulator is possible here. As you proposed: I do core, tests and the test peer; you do the on-device runs. |
| Network | Initially many hosts were blocked by the sandbox egress policy (`dl.google.com`, Codeberg, all relays). You lifted it at ~17:35 UTC. Before that I used hash-identical GitHub mirrors for three submodules; all submodule URLs are now canonical again. |
| Configure | Unmodified `./configure.sh` succeeds: submodules, boost, World map (`261004`), strings, symbols, drules. |
| APK | Unmodified `./gradlew assembleFdroidDebug -Parm64` builds in 11.5 min → `CoMaps-26100802-fdroid-debug.apk` (149 MB: debug symbols and HWASan). Maven Central answers HTTP 429 to this cloud IP under Gradle's parallel requests; it works with `-Dorg.gradle.internal.repository.max.tentatives=12 -Dorg.gradle.internal.repository.initial.backoff=3000` (command line only, no repo change). Note: debug builds enable HWASan on arm64, which needs Android 14+. Device builds for you will use `-PdisableHWAsan` or the `beta` type. |
| Desktop tests (clang 18, Debug) | `base_tests`, `coding_tests`, `geometry_tests`: all pass. `platform_tests` 63/68, `map_tests` 95/101, `kml_tests` 46/53. Every failure is environmental and pre-existing: downloader tests need the local HTTP test server; others are offscreen rendering, World-map/`countries.txt` version, and GPX/KML text formatting. Upstream CI excludes all three binaries from its Linux run. I recorded this baseline so that later hooks are diffed against it. Locales must be generated (`locale-gen en_US.UTF-8` …) as in CI, or `map_tests` segfaults in `GetMapLanguageCode()`. |
| PR #2269 | Read from the GitHub mirror branch `zy-live-location` and the Codeberg API, see [§15 Q7](#q7-comaps-poc-pr-2269). |

Code paths traced (all verified in source):

- **Location.** [`LocationHelper`](../android/sdk/src/main/java/app/organicmaps/sdk/location/LocationHelper.java)
  has a single provider with listeners.
  - Its interval is 500 ms normally and 1 s while recording a track.
  - It is stopped in the background by
    [`MwmApplication.onBackground()`](../android/app/src/main/java/app/organicmaps/MwmApplication.java)
    unless navigation, track recording, Android Auto or a pending fix keeps it alive. **Sharing needs
    one more condition there.**
  - [`TrackRecordingService`](../android/app/src/main/java/app/organicmaps/location/TrackRecordingService.java)
    is the template for a `location` foreground service with a Stop action. No
    `ACCESS_BACKGROUND_LOCATION` is needed: the service is started from the foreground.
- **Markers.** [`UserMark::Type`](../libs/map/user_mark.hpp) needs one new enum value (plus one
  `DebugPrint` case).
  - `ColoredMarkPoint` shows how to draw a coloured dot without new icon assets, so no
    `data/styles` or symbol changes are needed.
  - Marks are created and moved through `BookmarkManager::EditSession` on the GUI thread.
- **Crypto in core.** Monocypher 4.0.2 provides X25519, ChaCha20 (IETF), ChaCha20-Poly1305
  (IETF), constant-time compare and wipe. There is **no SHA-256 and no secp256k1** anywhere in the
  tree.
- **Key storage.** Android
  [`SecureStorage`](../android/sdk/src/main/java/app/organicmaps/sdk/util/SecureStorage.java) is
  plain `SharedPreferences` (not encrypted), see [§10.4](#104-key-storage-at-rest-question-5).
  - Backups are include-only (`bookmarks/`, `settings.ini`), so new files are excluded by default.
  - Secrets must never go into `settings.ini`.
- **Networking.** `HttpClient` (Android: `HttpURLConnection` via JNI) and a legacy TLS
  `PlatformSocket`. There is no WebSocket client and no OkHttp.
  - [`network_security_config`](../android/app/src/main/res/xml/network_security_config.xml)
    bundles ISRG Root X1 and others for API 24+, and also trusts user-installed CAs.
- **Deep links.** `MwmActivity.processIntent()` runs an array of `IntentProcessor`s, so an invite
  link needs one new processor class (a one-line hook).
- **JNI.** One `.cpp` per feature under `android/sdk/src/main/cpp/…`, listed in that `CMakeLists.txt`.
  The Android code is 100% Java (449 files, no Kotlin), although the Kotlin plugin is applied.

## 2. Requirements traceability

| # | Requirement | How it is met |
|---|---|---|
| 1 | Consent and visibility | Off by default behind a feature flag. Sharing starts only from the share sheet, with explicit recipients and duration. A foreground-service notification (with Stop) and an in-app indicator are shown while sharing. No silent mode exists: sharing refuses to start, and stops, while notifications for the app or its sharing channel are off, and a dismissed notification comes straight back (§11.3). Recipients have no message that could start, extend or alter a share; the protocol has no such message type at all. |
| 2 | Recipient control | Per-recipient `until`, Stop per recipient or all. Every membership change rotates the stream, so revocation is cryptographic and immediate (§4.4). |
| 3 | Confidentiality incl. metadata | No identity keys. Event keys are pseudonyms rotated per invite, per day or per stream, and no connection spans two days. The only `p` tag points at the invite's one-time pairing key, and there are no `g` tags. Payloads are padded per class, and inbox subscriptions are padded with decoys. What remains (IP addresses, timing, volume, keys used together within a day) is analysed in [§3](#3-threat-model). |
| 4 | Decentralisation | No server of ours. Any NIP-01 relay works. Publishing goes to all (default 3) relays, and the list is user-configurable, including self-hosted relays. Measured in [§6](#6-transport-evaluation-and-relay-test-results). |
| 5 | Minimal retention | Addressable "latest only" events with NIP-40 expiry: 15 min for positions, end of day + 1 h for channel state. No NIP-09 deletion requests, because relays keep those forever (§6.3). Viewers keep only the latest position per contact, in memory. Both ends erase keys, so copies of the ciphertext stay unreadable (§8.5). |
| 6 | Inert unless used | No initialisation without the flag. No connection without a paired contact. Then connections only while sharing, while pairing, or while the app is in the foreground and has contacts (decision D11). An unwatched share holds one connection (D17). The only background work without a share is a local daily ratchet that sends nothing (D16). |
| 7 | FOSS, de-Googled | All new dependencies are MIT, BSD or Apache-2.0. Location comes from the existing `LocationHelper` (native provider without Play services). No FCM: background receiving is out of scope. |
| 8 | Vetted crypto | Noise, HKDF, NIP-44 v2 (audited) and BIP-340 via libsecp256k1. No home-made primitives. Written spec plus test vectors. |
| 9 | Rebase-friendly | New library, new Java packages and new files. About a dozen small, marked hooks ([§8.3](#83-hooks-into-existing-code)). |

## 3. Threat model

**Assets**, most sensitive first:

1. Positions, current and past.
2. Who shares with whom (the contact graph).
3. Display names.
4. When someone moves or shares.
5. The fact of using the feature at all.

| # | Adversary | Can learn or do | Cannot |
|---|---|---|---|
| T1 | **A relay operator** (each relay) | **Network metadata:** the IPs of publishers and subscribers, connection times, events per pseudonymous key, update cadence (moving vs. stationary), how many connections follow a stream key, that the kinds belong to this protocol, and a coarse IP geolocation of both ends. **Linking within a day:** all keys that one connection uses, e.g. a sharer's stream and the channel keys it publishes states under, or a viewer's inbox keys and the streams it follows. **Who shares with whom, by IP address:** when sharer and viewers use the same relay, it sees which IP addresses follow the stream that another IP address publishes. **Contact count:** rounded up to a multiple of 8 by decoys; over a day, which inbox keys received events. **Active attacks:** drop, delay or replay events. | Read positions or names. Link keys across days, except by IP address or timing: no connection spans midnight UTC (spec §11). Tie invites or streams to a person. Forge or alter events (signatures, MACs). Replay an old grant or location: `seq` ordering stops it. |
| T2 | **Colluding relays or a global passive observer** | Everything in T1, correlated across relays and over time. With stable IPs, a long-term IP-level contact graph. | As above. Content stays confidential. |
| T3 | **An on-path network observer** (ISP, Wi-Fi) | The relay hostnames (TLS SNI), timing and volume, hence that you use Nostr relays and roughly when you share. | Any event content. TLS hides even the pseudonyms. |
| T4 | **A removed or expired recipient** | The old stream key, so updates published *before* its removal, if it recorded them. What it receives, a state without a grant and a reason-less `end`, is identical to the sharer stopping altogether. **Traffic analysis:** watching the sharer's relays, it may see a new stream start 30–120 s later and infer that the share went on. That inference is easier when few people use those relays (a self-hosted relay, for instance). If it operates one of the sharer's relays, it sees the sharer's IP address keep publishing (T1). It can also count the states published at that moment, which tells it roughly how many recipients the share had. | Decrypt the new stream, prove that it belongs to the sharer, or learn who the remaining recipients are. |
| T5 | **A malicious current recipient** | Your positions (by design). It can re-share them out of band (unpreventable). | Forge your positions to other recipients: the stream is signed by a key only you hold. Learn who else receives the share: grants are pairwise. Start, extend or alter your share. |
| T6 | **Someone who reads an invite** (photographed QR, compromised messenger) | **Race** the intended person and pair as an impostor. Its attempt stays on the relays, under its own key, until the invite expires. Both apps watch until then: if the real person shows up first or in time, both abort; if the inviter had already accepted, its contact is flagged and receives no share until the codes are compared. If the real person never shows up, only comparing codes reveals the impostor, which is why contacts paired by link start "unverified". **Disrupt** the pairing: any competing attempt makes both apps abort and say that the invite was used elsewhere. **Passive interception** reveals only the relays already in the invite: step 1 carries nothing, and both names travel under `ee`-derived keys. Mitigations: codes on both screens, the unverified status, single-use invites, expiry (10 min for QR). | Impersonate the inviter: its steps must be signed by the key whose public half is in the invite. Replace or delete anyone's pairing events. Learn channel keys from a pairing it did not actively complete: `ee` Diffie-Hellman. |
| T5b | **A malicious contact as sharer, inviter or recipient** (for example a stalker you paired with) | **Choose the relays your phone connects to for it**: its stream relays when you view its share or send watch signals, its invite's relays while you pair and until the invite expires, its inbox relays when you send it states (also when you stop sharing with it). If it runs one of them, it learns your IP address, hence your rough location and provider, and when your app talks to it, e.g. when your map is open. You never have to share with it for this to happen. Mitigations: relay consent (spec §11): without asking, your phone uses only your own relays, the defaults and relays you approved; for any other relay a contact names, the app asks once, naming the contact and the relay. Invites live at most 24 hours. "Hide" stops all connections for that contact. | Make your phone connect to a relay you did not approve. Keep you watching an invite for more than a day. Learn anything about you from relays that you and other contacts use, beyond what T1 says about every relay operator. |
| T6b | **Someone who rewrites an invite in transit** (substitutes its own) | **Sit in the middle** of both pairings. The protocol cannot see it: the two screens show different codes, matching by chance with probability 10⁻⁶. It cannot grind the codes: the joiner commits to its key first, each side accepts one message per step, and the code comes from the keys, not the transcript (spec §6.3–6.4). Only comparing codes reveals it. | Anything, once the users have compared codes. |
| T7 | **Device thief or forensic examiner** | **Before the first unlock after a reboot:** nothing; the app's files are in credential-encrypted storage. **After the first unlock, even with the screen locked:** Android keeps the storage keys in memory, and forensic tools target exactly this state. With an exploit that runs code on the device, an attacker gets what the app holds now: the current channel keys, and the latest positions while the app is running (in memory). If the app has not run for days, its stored chain keys are that old (D16). | Past channel keys (ratchet) and past streams (erased at both ends), hence the content of archived ciphertext. No positions are stored on disk. The limits of key erasure on flash are in §10.4. |
| T8 | **Malware or root on the device** | Out of scope: it can read everything the app can. | — |
| T9 | **CoMaps project / app distribution** | Out of scope: it ships the code. It plays no role in operation; no CoMaps server is involved. | — |
| T10 | **Other relay clients** (scrapers) | What is published: pseudonymous keys, kinds, timing and sizes. They can archive the ciphertext. | IP addresses, connections and subscriptions, which only relays see. Content, as for T1. |

Residual leaks worth stating plainly (they go into the user-facing explanation screen,
[§11.6](#116-what-relays-can-see-one-screen)):

- **IP addresses.** Inherent to any internet service. Tor or proxy support is out of scope for v1,
  but not precluded (OkHttp supports proxies).
- **Timing and cadence.** Update times reveal when you are moving; with decision D4 they also reveal
  when someone is watching you. Constant-rate cover traffic would hide this at a large battery cost
  (not proposed).
- **Viewer counts.** A relay can count the connections subscribed to a stream.
- **Who follows whom, by IP address.** A relay used by both sides sees which IP addresses follow
  the stream that another IP address publishes. Only routing through Tor or a proxy would hide it.
- **Keys used together within a day.** A connection links the keys it uses. No connection crosses
  midnight UTC, so beyond the day boundary only IP addresses and timing link them.
- **Number of contacts.** Rounded up to a multiple of 8 by decoys. Over a day, a relay sees which
  of the keys actually received events.
- **Ciphertext copies.** Relays that ignore NIP-40, and anyone else, can keep copies. They stay
  unreadable once both ends have erased the keys (§8.5, §10.4).
- **Relays chosen by contacts.** A contact who runs a relay it names learns your IP address whenever
  your phone uses that relay for it. Relay consent (§11.4) limits this to relays you approved
  (T5b).
- **Protocol fingerprint.** The kind numbers identify the protocol.

## 4. Protocol overview

Full byte-level detail: [LIVE_LOCATION_PROTOCOL.md](LIVE_LOCATION_PROTOCOL.md). In short:

### 4.1 Pairing

1. A shows a QR code (or sends a link) containing a 32-byte one-time secret, A's one-time pairing
   public key, an expiry and A's relays (123 bytes, a 183-character link).
2. B's app makes a one-time pairing key of its own. With it, it publishes on A's relays a commitment
   to its fresh Noise key, authenticated with the secret.
3. A's app answers with Noise `NNpsk0_25519_ChaChaPoly_SHA256` message 1, signed with A's pairing
   key and carrying nothing else. B's app accepts step 1 only under the key from the invite. It
   replies with message 2, which opens the commitment and carries B's name and relays.
4. A's app shows "Bob wants to connect — code 294 805" and asks A to accept. B's app shows the same
   code.
5. A's decision is sent as the fourth message, together with A's name and relays. Both apps derive
   two per-direction channel roots from the handshake and erase everything else. Until the invite
   expires, they keep watching the relays for anyone else using it.
6. B's app confirms with a first, share-less state on the new channel. Until it arrives, A's app
   shows B as "waiting": pairing is complete only when both sides hold the contact.

Invites live at most 24 hours. B's app connects to A's relays only after relay consent (§11.2): A
chose them, and if A ran one, it would learn B's IP address.

The commitment, and each side accepting exactly one message per step, make the 6-digit code
meaningful. Without them, a man in the middle could try keys offline until both screens show the
same code. The code comes from the keys rather than from the transcript, so varying a message's
content does not help either (§5, spec §6.3–6.4).

Each side signs its own pairing messages, so nobody who reads the invite can sign as A, or replace
or delete anyone's messages. Someone racing B is visible to both apps until the invite expires. Before
the pairing ends, both apps then abort; after, the contact is flagged. A contact stays "unverified"
until its user confirms that the codes matched (§11.2).

### 4.2 Channels

Each direction is a hash chain that advances every UTC day (forward secrecy). Each day's key
yields a fresh event signing key and a NIP-44 key. A direction has one addressable slot, the
sender's *current state* towards that contact: its relays plus, while sharing, a grant
`{until, stream pubkey, stream key}`.

### 4.3 Sharing

The sharer creates a random **stream** (signing key and encryption key). It publishes each position
as the stream's single addressable event (latest-only, 15-min expiry). Recipients get the stream
pubkey and key through their channel. All payloads are padded per class, so a location, an end, a
grant and a "not sharing" state cannot be told apart by size.

### 4.4 Revocation and time limits

On any membership change, at each `until`, and at each new day, the sharer starts a new stream and
grants it to the remaining recipients only.

- At that moment the sharer first publishes every state, in random order: new grants for those who
  remain, and a state without a grant for those removed. Then it publishes the old stream's `end`.
  No `end` carries a reason.
- The new stream stays silent for a random 30–120 s.
- Stopping altogether looks the same from outside: the states, then the `end`.
- Recipients also enforce `until` locally, and erase a stream key as soon as it is replaced or
  ended.
- A removed recipient therefore cannot read later updates, and stops seeing the share at once. What
  it receives is exactly what "stop sharing" would have sent. It can only guess from traffic that a
  new stream started on the sharer's relays (T4).

### 4.5 Watch signals (D4)

While a viewer has the map open, it sends a small ephemeral, encrypted "watching" signal to the
sharer about once a minute. The sharer then sends every fix, rather than only larger moves and a
5-minute heartbeat. This is what reconciles "follows within ~5 s" with an acceptable battery cost.

## 5. Cryptographic construction and rationale

| Need | Choice | Why |
|---|---|---|
| Nostr event ids and signatures | SHA-256 and BIP-340 Schnorr via **libsecp256k1** | Mandatory for Nostr (relays verify). libsecp256k1 is Bitcoin's reference implementation, the most scrutinised secp256k1 code there is. |
| Pairing | **Hash commitment, then Noise `NNpsk0_25519_ChaChaPoly_SHA256`** with the invite secret as PSK | A standard handshake pattern with a published formal analysis ([Noise Explorer: NNpsk0](https://noiseexplorer.com/patterns/NNpsk0/)) and official vectors (cacophony). The PSK authenticates both sides, and the inviter's pairing key in the invite authenticates the inviter's Nostr events, so a reader of the invite cannot pose as the inviter. Ephemeral `ee` Diffie-Hellman keeps later messages secret even if the invite leaks afterwards. The 6-digit code comes from the key schedule (the `Split()` output), which depends only on the PSK and the two ephemeral keys. The commitment (the joiner's hash of its ephemeral key, sent first) and the rule that each side accepts one message per step stop a man in the middle from grinding keys to make the codes match. Matrix SAS, ZRTP and Bluetooth numeric comparison use the same technique. X25519 and ChaChaPoly come from Monocypher (already in tree). |
| Channel keys | HKDF-SHA256 hash chain advanced per UTC day; per-day signing key and NIP-44 key | Forward secrecy with one-day granularity: once both ends have erased a day's key, a seized device cannot decrypt that day's grants. The pairing roots are erased right after first use. Pseudonyms change daily. No extra round-trips: both sides derive the day's keys from the clock. |
| Payload encryption | **NIP-44 v2**, conversation key from our derivations | The Nostr ecosystem standard, audited by Cure53 (2023), with vectors. HMAC-SHA256 + ChaCha20. Its padding plus our fixed-size classes hide content length. |
| Stream authenticity | Random per-stream key, known only to the sharer, signs the stream events | Recipients share the decryption key but cannot sign, so they cannot forge the sharer's positions. Signal's sender keys separate authenticity from confidentiality the same way. |
| Group key management | **Sender keys** with rotation on membership change | One event per update regardless of group size (§7). Revocation by re-keying. MLS/Marmot would add post-compromise security for *many-to-many* groups at a large complexity cost; here there is one sender per stream. |

What we explicitly do **not** get:

- **Post-compromise security on a channel.** After a device compromise the attacker can follow
  future channel keys until the contacts re-pair; a "re-pair" action is the remedy.
- **Deniability towards a recipient.** Recipients cannot prove *who* signed a stream, since stream
  keys are not identity-bound, but they hold the plaintext anyway.
- **Post-quantum security.** None, like all of Nostr.

SHA-256 source: libsecp256k1 implements SHA-256 and HMAC-SHA256 internally (`src/hash_impl.h`,
~300 lines) but does not export them. I propose a tiny C translation unit that includes that file
from the pinned submodule and exports two functions, so no third-party code is added beyond the
submodule we need anyway (decision D9). HKDF (RFC 5869), NIP-44 and Noise's symmetric state are
specified constructions over those primitives. They are written once in C++ and checked against
the published vectors.

## 6. Transport evaluation and relay test results

### 6.1 Why Nostr

| Option | Verdict |
|---|---|
| **Nostr relays** | Hundreds of independent public relays with a trivially simple protocol (JSON over WebSocket). Addressable events with expiry give exactly the "latest position only" semantics. Self-hosting is easy (strfry, nostr-rs-relay, khatru). No accounts. **Chosen.** |
| Matrix | Accounts on homeservers that store room history and see membership and the contact graph. Heavy E2EE stack (vodozemac is Rust). Fails requirements 3 and 5. |
| XMPP + OMEMO | Accounts and server-side rosters, i.e. a visible contact graph. Fails requirement 3. |
| SimpleX SMP | The best metadata model of the lot (no user identifiers, unidirectional queues). But no Java/C++ client library: a Haskell reference with a complex wire protocol, and much more to implement and review. A good candidate for a future transport; not v1. |
| MQTT brokers (OwnTracks style), ntfy | Few public servers, topics visible to the server, no expectation of operator independence. Weaker on requirement 4. |
| Tor, mesh (Reticulum, Briar) | Out of scope for v1 per the brief. NLL is transport-agnostic above "publish/subscribe signed events", so it does not preclude them. |

### 6.2 Existing designs (question 2)

- **NIPs.** No NIP covers private live location. The only location-related tag is the geohash `g`
  tag (NIP-52, NIP-66, NIP-CC), which is for *public* events and must not be used here.
- **NIP-78** (kind 30078, app data) is unsuitable. It asks relays to serve those events only to
  their author after AUTH, so recipients could not read them.
- **NIP-59 gift wrap** p-tags a recipient's real key. **NIP-17** builds DMs on it. Neither fits a
  no-identity design.
- **Marmot** (successor of NIP-EE, MLS over Nostr) publishes KeyPackages under the user's identity
  key, and gift-wraps Welcomes to identity keys. That violates requirement 3 at onboarding. Its
  group traffic uses fresh per-event keys plus a random group-id tag, an idea compatible with ours.
  For a single-sender stream it brings MLS's full complexity for no gain over sender keys.
- **LocaPeer** (verified in its source):
  - identity-signed events, `p`-tagged with the recipient's real key;
  - regular kinds 1040–1060, which collide with registered 1040 (OpenTimestamps) and 1059 (Gift Wrap);
  - per-recipient NIP-44 copies;
  - Play-services location.
  - Its "Live View" (speed up while watched) inspired D4.
- **ntrack**:
  - one shared group key, so a member cannot be revoked without re-keying everyone;
  - a regular kind, 3434, with 24 h expiry, so relays keep the whole day's trail;
  - throwaway sender keys, as we use.
- **CoMaps PoC #2269**: see [§15 Q7](#q7-comaps-poc-pr-2269).

I therefore propose a new, small, self-contained convention (NLL v1) built only from existing NIPs
(01, 40, 44) plus Noise. It is written so that it could later be proposed as a NIP.

### 6.3 Relay tests (question 1)

Method: [`relay_probe.py`](../tools/python/live_location/relay_probe.py) (features),
[`relay_probe_sustained.py`](../tools/python/live_location/relay_probe_sustained.py) (limits, expiry
lag, 3-min cadence) and [`relay_soak.py`](../tools/python/live_location/relay_soak.py) (30 min). They
use **fresh random keys for every test and never AUTH, PoW or payment**, the exact kinds and shapes
of NLL events, and a small, polite volume (≤ 400 events per relay in total). The harness was first
validated against a locally built **strfry** (the software nos.lol reports in NIP-11; relay.damus.io
reportedly runs it too). Raw
results are in [`tools/python/live_location/results/`](../tools/python/live_location/results/).
Network paths ran from a cloud datacenter through an egress proxy, so absolute latencies are
pessimistic for phones.

Round 1, feature matrix (2026-10-09). It covers 20 relays, plus a re-run for the two relays first
seen in round 2. "Y" means yes and "n" no; latency is publish → second connection.

| Relay | Software | Kind 30484 from fresh key | Latest-only replace | Live fwd | Ephemeral fwd | Expired event hidden within¹ | Expired at ingest rejected | NIP-09 `a` honoured | Burst 10 @ 1/s, 5/s |
|---|---|---|---|---|---|---|---|---|---|
| nos.lol | strfry | Y | Y | Y 191 ms | Y | ≤ 5–9 s | Y | Y | 0 refused |
| relay.primal.net | custom | Y | Y | Y 218 ms | Y | ≤ 15 s | Y | Y | 0 refused |
| nostr.mom | strfry | Y | Y | Y 242 ms | Y | ≤ 5 s | Y | Y | 0 refused |
| relay.nostr.net | custom | Y | Y | Y 247 ms | Y | ≤ 15 s | Y | Y | 0 refused |
| nostr.data.haus | strfry | Y | Y | Y 287 ms | Y | ≤ 15 s | Y | Y | 0 refused |
| relay.snort.social | memlay | Y | Y | Y 139 ms | Y | **never** (still served 40 s after) | **n** | **n** | 0 refused |
| nostr.oxtr.dev | strfry | Y | Y | Y 283 ms | Y | ≤ 15 s | Y | **n** | 0 refused; dropped the connection in round 2 |
| nostr-pub.wellorder.net | nostr-rs-relay | Y | Y | Y 131 ms | Y | ≤ 5 s | Y | Y | 0 refused; **50 authors OK, 100 time out**; dropped connections in round 2 |
| relay.wellorder.net | nostr-rs-relay | Y | Y | Y 123 ms | Y | ≤ 5 s | Y | Y | as above |
| relay.nostr.wirednet.jp | strfry | Y | Y | Y 362 ms | partial: connection closed mid-probe in round 1 | ≤ 5 s | — | — | 3-min run at 1 event / 5 s: 0 refused |
| offchain.pub, nostr.bitcoiner.social | strfry + WoT | 1st event only | — | — | — | — | — | — | refused: "pubkey is not in our web of trust" |
| relay.nos.social, purplepag.es | strfry, custom | **n** | — | — | — | — | — | — | "kind not allowed" |
| nostr.einundzwanzig.space | ? | **n** | — | — | — | — | — | — | "NIP-05 verification needed" |
| nostr.wine, nostr.land, nostr21.com | paid | **n** | — | — | — | — | — | — | "restricted: sign up / pay" |
| relay.damus.io | (strfry, reportedly) | 503 on WebSocket upgrade from this cloud IP (both rounds); untestable here, likely fine from phones | | | | | | | |
| relay.nostr.band, relay.nostr.bg, relay.0xchat.com, relay.nostrich.land, relay.mostr.pub | — | unreachable (timeout, 502, or redirect to a non-relay) | | | | | | | |

¹ Queried 5, 15 and 40 s after expiry (round 2); round 1 checked 4 s after. strfry purges expired
events with a cron job every 9 s, so an event can be served a few seconds past its expiry. That is
bounded and harmless here.

Other findings:

- **Ephemeral ≠ unstored.** strfry stores ephemeral events for up to 300 s and serves them to later
  queries. Relays built on strfry, and relay.primal.net and relay.nostr.net, did so in the probe. The
  threat model treats signals as briefly retained.
- **NIP-09 deletion requests are themselves kept forever.** That is per spec, and strfry also blocks
  re-publication after them. NLL therefore never sends kind 5; ends are expressed by replacing the
  slot, and expiry cleans up.
- **No idle disconnects** in 180 s on any accepting relay. No AUTH challenges, except nostr.land
  (paid).
- **Keep-alive pings** (round 4, 2026-10-10: one idle connection per relay for 10 minutes,
  [`relay_keepalive.py`](../tools/python/live_location/relay_keepalive.py)). nos.lol and nostr.mom
  (strfry, configured that way) ping every **240 s**. relay.nostr.net, relay.primal.net and
  nostr.data.haus ping every **55 s**, strfry's default. relay.snort.social never pings, and closes
  an idle connection after 300 s. Each ping wakes a phone's radio, which is why an unwatched share
  keeps only one connection open (§10.3, D17).
- **Pairing layout** (round 5, 2026-10-11,
  [`relay_probe_pairing.py`](../tools/python/live_location/relay_probe_pairing.py)): each party signs
  its own pairing events, and the joiners' carry a `p` tag (spec §6.3). On nos.lol, nostr.mom,
  relay.primal.net, nostr.data.haus and relay.nostr.net:
  - kind 30484 events with tags `d`, `p` and `expiration` were accepted;
  - a live `#p` subscription received them (p50 ≈ 0.2 s);
  - a later `#p` query returned the events of two authors that share the same `d`, so the relay did
    not replace one author's event with another's;
  - a newer event replaced only its own author's older one;
  - an `authors` query found the inviter's event.

  relay.nostr.net was down for hours that night: HTTP 500 from 00:18 UTC, then timeouts until at
  least 05:40 UTC, its NIP-11 endpoint included. It is a live example of one default relay failing.
  It was back by 09:07 UTC, when it passed every check above. No rate limiting at 0.2 events/s sustained or 5 events/s in bursts. The only refusals were
  policies: paid, web of trust, NIP-05, kind whitelists.
- **Author caps.** nostr-rs-relay handles 50 authors per filter but not 100, so the spec caps filters
  at 50.

Round 3, 30-minute soak (2026-10-09 17:47–18:17 UTC). One addressable update per 5 s per relay
(360 events), with a second connection subscribed live; both connections reconnect automatically.
"Missed" means the live copy did not arrive within 5 s.

| Relay | Accepted | Missed | Disconnects (pub/sub) | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| nos.lol | 360/360 | 1 | 2/2 | 231 ms | 269 ms | 299 ms | 346 ms |
| nostr.mom | 360/360 | 3 | 1/2 | 240 ms | 276 ms | 300 ms | 307 ms |
| relay.nostr.net | 360/360 | 0 | 0/0 | 267 ms | 322 ms | 374 ms | 880 ms |
| relay.primal.net | 360/360 | 0 | 1/0 | 230 ms | 3248 ms | 4010 ms | 5347 ms |
| nostr.data.haus | 359/359 | 1 | 0/0 | 258 ms | 1609 ms | 3276 ms | 6255 ms |
| relay.snort.social | 360/360 | 1 | 2/1 | 142 ms | 164 ms | 186 ms | 204 ms |

Reading it:

- **No refusals** at this rate on any relay.
- **A few disconnects per half hour** are normal: the relay pool must reconnect and resubscribe
  silently.
- **Misses** (0.3–0.8 %) coincide with those reconnects. Because a viewer reads all of a sharer's
  relays and keeps the first copy, an update is lost only if every relay misses it at once.
- **Effective latency** is the minimum over the relays, so one relay's tail (Primal's multi-second
  p95) is masked by the others.

**Recommended defaults** (decision D5): `wss://nos.lol`, `wss://nostr.mom`, `wss://relay.nostr.net`.

- Three operators and at least two implementations (strfry and relay.nostr.net's own).
- All honour NIP-40 and latest-only replacement.
- Tight tails in the soak (p99 ≤ 374 ms); relay.nostr.net had zero disconnects.
- Alternates: relay.primal.net (long latency tail) and nostr.data.haus.
- Not recommended:
  - relay.snort.social: no NIP-40 support, so events would be retained;
  - nostr-rs-relay hosts: dropped connections in our runs;
  - web-of-trust, paid and kind-whitelisted relays.
- The app will health-check relays and show a warning when fewer than two are reachable.
- **Self-hosting** (your note on D5). For a small private circle, two self-hosted relays on different
  hosts cut third-party relay operators out entirely; strfry needs a few minutes to set up. The
  flip side: whoever runs a relay sees its metadata (T1). If a member of the circle runs it, they see
  everyone's IP addresses and timing, and keep seeing them after being removed from a share (T4).

## 7. Fan-out: 1, 10 and 50 recipients

Per location update, sharer side, three relays. One stream event is 814 bytes, about 1.16 KB on the
wire per relay including WebSocket, TLS, TCP/IP and the relay's `OK`. A channel state is 1154 bytes.

| Recipients | Per-recipient copies (LocaPeer style) | **Sender key (NLL)** | MLS (Marmot) |
|---|---|---|---|
| 1 | 1 event, 3.5 KB | 1 event, 3.5 KB | 1 event + group state |
| 10 | 10 events, 35 KB | **1 event, 3.5 KB** | 1 event; commits O(log n) on change |
| 50 | 50 events, 175 KB, 10 events/s at 5 s cadence, near relay rate limits | **1 event, 3.5 KB** | 1 event; commits on change; every member must process every commit |
| Upload per hour at 5 s cadence, 50 recipients | ≈ 125 MB | **≈ 2.5 MB** | ≈ 2.5 MB + commits |
| Membership change | nothing to do | one state per remaining recipient (~3.5 KB each) | Commit + Welcome; members must be online to stay in sync |
| Revocation | stop encrypting to them | rotate; cryptographic | MLS remove; cryptographic, plus post-compromise security |

Sender keys dominate for this one-to-many case. MLS's extra property, post-compromise security among
many senders, does not apply to a single-sender stream and would cost a large dependency (OpenMLS is
Rust; MLS++ needs OpenSSL). Viewer-side download is the same in all three: one event per update per
subscribed relay.

## 8. Architecture and code placement

### 8.1 Components

```
libs/live_location/                 NEW C++ library (core; no UI, no platform code)
  crypto/        sha256 shim (libsecp256k1), hkdf, nip44, noise_nnpsk0, keys, random
  nostr/         event serialisation/id/sign/verify, relay message JSON (jansson)
  protocol/      invites, pairing, channels, state, stream, signals (= NLL v1)
  relay_pool     connections via an abstract WebSocket interface, one epoch per connection;
                 publish/OK tracking, subscriptions (decoy-padded inbox), dedupe,
                 reconnect/backoff, relay health
  store          contacts, chain keys, pending pairings; one file, encrypted with a data key
                 that rotates whenever secrets are erased (no positions, no stream keys)
  manager        the state machine: pairing, sharing, viewing, timers, cadence and
                 connection policy; callbacks for UI and map; runs on its own task loop
  live_location_tests/   unit tests (incl. all vectors) + integration tests against an
                 in-process fake relay (drops, delays, 2 of 3 down, replay)
3party/secp256k1        NEW git submodule (bitcoin-core/secp256k1 v0.7.0; extrakeys + schnorrsig only)
libs/map/live_location_marks.{hpp,cpp}   NEW: contact dots via BookmarkManager (ColoredMarkPoint-style)
android/sdk/src/main/cpp/app/organicmaps/sdk/livelocation/   NEW JNI: manager facade, WebSocket bridge,
                 key unwrap bridge
android/sdk/src/main/java/app/organicmaps/sdk/livelocation/  NEW: OkHttp WebSocket transport, Keystore
                 key wrapper, JNI facade, models
android/app/src/main/java/app/organicmaps/livelocation/      NEW: contacts screen, pairing screen (QR,
                 link, paste), share sheet, LiveLocationService (FGS), notification, settings,
                 explanation screen, map indicator, invite IntentProcessor
android/app/src/main/res/.../*live_location*                 NEW layouts, strings (English first)
tools/python/live_location/          NEW (this phase): reference implementation, vectors, relay
                 probes; Phase 2: test peer CLI
docs/LIVE_LOCATION*.md               NEW
```

Why the core is C++ and not Java:

- Maintainers asked for exactly that on the PoC: x7z4w's review says "Some things should be moved
  to core, to de-duplicate logic with Android/iOS", and "Why not using the introduced crypt logic in
  core?".
- iOS and desktop stay possible later without rewriting the protocol.
- A desktop test peer reuses the same code.

WebSocket and TLS stay on the platform side (OkHttp on Android), following the existing `HttpClient`
pattern. Bundling a TLS stack into native code would mean a second certificate store to maintain.

### 8.2 Threads and data flow

- **The manager** runs on its own `base::TaskLoop` thread. All protocol state is mutated only there.
- **Transport:** OkHttp callbacks → JNI → post to the manager.
- **Location fixes:** `LiveLocationService` is a `LocationListener` (like `TrackRecordingService`).
  Fixes go → JNI → manager.
- **Map updates:** manager → `GetPlatform().RunTask(Platform::Thread::Gui, …)` →
  `LiveLocationMarks` → `BookmarkManager::EditSession`.
- **UI:** manager callbacks → JNI → `UiThread`.

### 8.3 Hooks into existing code

Each hook is marked `// Live location (NLL): …`.

| File | Change | Size |
|---|---|---|
| `.gitmodules`, `3party/CMakeLists.txt` | add secp256k1 submodule + `add_subdirectory` | ~6 lines |
| `libs/CMakeLists.txt` | `add_subdirectory(live_location)` | 1 line |
| `libs/map/user_mark.hpp/.cpp` | `LIVE_LOCATION` enum value + `DebugPrint` case | 2 lines |
| `libs/map/CMakeLists.txt` | add `live_location_marks.*` | 2 lines |
| `libs/map/bookmark_manager.cpp` | (optional) make the dots tappable in `FindNearestUserMark` | 1 line |
| `android/sdk/src/main/cpp/CMakeLists.txt` | JNI sources + link `live_location` | ~4 lines |
| `android/app|sdk/build.gradle.kts`, `gradle/libs.versions.toml` | OkHttp, qrcodegen | ~4 lines |
| `AndroidManifest.xml` | service, activity | ~10 lines |
| `MwmApplication.onBackground()` | keep location while sharing | 2 lines |
| `LocationHelper.calcLocationUpdatesInterval()` | slower interval while sharing in the background | 2 lines |
| `MwmActivity` | menu entry, indicator, intent processor. `comaps://` already carries the ge0 short links (`comaps://<10 chars>/<name>`), so the invite processor goes before that handler. `live/pair#` cannot be a ge0 code: `/` and `#` are outside ge0's alphabet | ~10 lines |
| settings (prefs XML + fragment) | experimental toggle | ~10 lines |

### 8.4 Feature flag

A runtime preference "Live location sharing (experimental)", default **off**. While off, nothing in
the feature is constructed: no library init, no threads, no files, no network. When it is switched
off, all shares stop and connections close. Contacts are kept until deleted, and the screen offers
"delete all live-location data".

### 8.5 Persistence

One file, `live_location.dat`, in Android's `noBackupFilesDir`.

What it holds:

- contacts: name, relays, the chain key of each direction (for the oldest epoch still needed only),
  and sequence counters;
- the decoy seed (spec §11);
- pending pairings: until they end, the PSK, the pairing secret, the Noise ephemeral key and the
  step 0; until the invite expires, what watching for conflicts needs: the MAC key, the inviter's
  pairing key and the ids of the accepted events (spec §6.3);
- each contact's verified and flagged status;
- the active share's settings (recipients and their `until`), so that the app can offer to resume
  after its process was killed.

What it never holds:

- positions, on either side. Viewers keep the latest position per contact in memory, and fetch it
  again from the relays when they start;
- stream secrets and stream keys. They live in memory only. After a process death, the sharer starts
  a new stream once the user resumes, and recipients re-read their grants from the relays.

How it is protected:

- It is encrypted with XChaCha20-Poly1305 (Monocypher) under a 32-byte data key, which an Android
  Keystore AES-256-GCM key wraps.
- **Rotation on erasure.** Whenever secrets in the file are erased (a ratchet step, a pairing ending,
  a contact deleted), the app makes a new data key and a new Keystore key. It writes the file under
  them (temporary file + rename), then deletes the old Keystore key. Old versions of the file that
  survive on flash, since a rename does not erase blocks, are encrypted under a data key that
  nothing can unwrap any more. §10.4 has the limits.

A sharer whose process dies stops sharing; it does not restart by itself. When the user next opens
the app, it offers "Resume sharing with Bob until 18:30?". (Android 12+ does not allow starting a
location foreground service from the background anyway.)

## 9. Dependencies

| Dependency | Where | License | Size | Why |
|---|---|---|---|---|
| **libsecp256k1 v0.7.0** (git submodule) | C core | MIT | ~55 KB of code (x86-64 `-Os`, measured) with 2 KiB tables (`ECMULT_WINDOW_SIZE=2`, `ECMULT_GEN_KB=2`) instead of the default ~1.1 MB; sign 30 µs, verify 74 µs (measured) | BIP-340 is mandatory for Nostr; reference implementation; also supplies SHA-256/HMAC (D9) |
| Monocypher 4.0.2 | already in tree | BSD-2 / CC0 | — | X25519, ChaCha20(-Poly1305), wipe |
| jansson | already in tree | MIT | — | relay message parsing |
| **OkHttp 4.12.0** (+ Okio 3.6) | Android sdk | Apache-2.0 | jars 790 KB + 360 KB; est. 0.3–0.4 MB after R8 (to be measured) | WebSocket client: TLS, ping/pong, timeouts, proxy support; F-Droid-friendly; Kotlin stdlib already present |
| **Nayuki qrcodegen 1.8.0** | Android app | MIT | 38 KB jar | show the invite QR |
| *(not proposed for v1)* ZXing + CameraX | — | Apache-2.0 | ~1.5 MB + camera permission | in-app scanner (D8) |
| coincurve, cryptography, websockets | `tools/python` only | MIT / Apache-2.0 / BSD | — | reference implementation, vectors, relay probes, test peer |

Alternatives I measured or considered for WebSocket: Java-WebSocket 1.6.0 (MIT, 141 KB, needs
slf4j) and nv-websocket-client 2.14 (Apache-2.0, 125 KB, unmaintained since 2021). OkHttp is
larger but by far the most battle-tested (D7).

## 10. Android specifics: location, power, data, key storage

### 10.1 Minimum Android version (question 4)

Proposal: the feature requires **API 24 (Android 7.0)**. The app's `minSdk` stays 21; the entry
point is hidden below 24 (D6).

- API 24 is when `network_security_config` trust anchors apply. Most relays use Let's Encrypt, whose
  ISRG Root X1 is missing from Android < 7.1.1's store; the app's config already bundles it, but
  only API 24+ honours it.
- Keystore AES needs API 23.
- The alternative, a custom `TrustManager` for API 21–23, is code we could not test on real devices.

TLS 1.2 is available from API 20 and TLS 1.3 from API 29; OkHttp uses the platform TLS.

### 10.2 Location

- Fixes come from the existing `LocationHelper`, so the user's provider choice (native, or fused via
  microG) is respected and Play services are never required.
- A `location` foreground service (`LiveLocationService`, modelled on `TrackRecordingService`) is
  started from the share sheet, so no background-location permission is needed.
- `MwmApplication.onBackground()` gains one condition: keep location running while sharing.
- In the background the service asks for a slower interval (below) through a small hook in
  `LocationHelper.calcLocationUpdatesInterval()`. When the map is in the foreground, its normal
  500 ms interval applies and the sharer still publishes at the cadence below.

### 10.3 Update policy, battery and data (question 6, decision D4)

| Mode | When | Publish | GPS request |
|---|---|---|---|
| **Live** | a viewer's `watch` signal arrived in the last 120 s | every fix (≥ 3 s apart; moved ≥ 3 m, or ≥ 15 s elapsed) | 2 s, high accuracy |
| **Idle** | nobody watching | when moved ≥ 50 m (≥ 30 s apart), else heartbeat every 5 min | 30 s, balanced |
| **Ending** | user stops, `until` passes, battery ≤ 5 % | final `end` + states | stop |

- Viewers send `watch` every 60 s while the map is visible and the contact's share is active.
- Opening the map also immediately fetches the stored latest position. So "B sees A within ~5 s"
  holds from the first fix after B opens the map, end-to-end latency being p50 ≈ 0.25 s in the soak
  test.
- The idle heartbeat (5 min) keeps the 15-minute-expiring latest position alive on relays.

**Connections (decision D17).** Every wake of the cellular radio costs a "tail" of several seconds
at high power. A publish is such a wake, and so is every keep-alive ping a relay sends to an idle
connection. Measured pings (§6.3): every 240 s on nos.lol and nostr.mom, every 55 s on
relay.nostr.net. Three idle connections to the default relays would wake the radio about 95 times an
hour, or about 195 times if all three used strfry's default 55 s. Hence:

| Situation | Connections held open | Client pings |
|---|---|---|
| Sharing, nobody watching (idle) | **One**, to the first reachable relay in the user's list (the default list starts with nos.lol). It carries the inbox subscription, so it hears watch signals and states. The other relays are connected only to publish, and closed after 60 s without traffic. | None. The relay's pings keep the connection alive, and the heartbeat publish (no `OK` within 10 s) detects a dead one. |
| Sharing, watched (live) | All home relays. Publishing every few seconds keeps the radio up anyway. | None |
| Viewing (app in the foreground, D11) | Own home relays, plus the approved relays of contacts sharing with me (relay consent, §11.4) | None |
| Otherwise | None | — |

Viewers send each watch signal to all of the sharer's relays, so the sharer can listen on any one of
them. If its listening relay fails, the sharer moves to the next one. If the connection dies
silently, the next heartbeat notices, so live mode then starts up to one heartbeat (5 min) late,
but it does start. OkHttp does not report the server's pings to the app, so the list order, not a
measured ping interval, picks the listening relay.

Estimated budgets for one hour, sharer side, three relays, on LTE. They are estimates, and the
measurement the DoD requires replaces them. The model: a radio wake costs about 5–10 J (some 10 s at
0.5–1 W), GNSS draws about 0.05–0.1 W, and on a 15 Wh battery 1 %/h is 0.15 W. On Wi-Fi a wake costs
far less, and every idle case drops below 1 %/h.

| Scenario | Radio wakes per hour | Data | Battery |
|---|---|---|---|
| Constant 5 s cadence (no D4) | continuous | ≈ 2.5 MB up+down | **≈ 4–8 %/h** |
| D4, watched the whole hour | continuous | ≈ 2.5 MB | ≈ 4–8 %/h |
| D4, unwatched, walking (a publish every ~40 s) | ≈ 100–150 | ≈ 0.4 MB | **≈ 1.5–3.5 %/h** |
| D4, unwatched, stationary, **one** listening connection (D17) | ≈ 27 (12 heartbeats, 15 pings) | ≈ 0.2 MB (TLS handshakes for the publishes) | **≈ 0.5–1 %/h** |
| … the same, with all three connections held open | ≈ 107 (12 + 95) | ≈ 0.05 MB | ≈ 1.5–2.5 %/h |
| … the same, if all three relays pinged every 55 s | ≈ 207 (12 + 195) | ≈ 0.05 MB | ≈ 2–4 %/h |
| Viewer, map open, 3 relays | — | ≈ 2 MB down (each update arrives once per relay) | screen dominates |

The previous draft left out the listening connections altogether. Counting them, holding all three
connections open costs an unwatched, stationary share two to three times what that draft estimated.
D17 takes most of that back.

The cost of D4 is metadata (see T1): relays can see that a viewer's signal is followed by faster
updates on some stream. Both sides get a setting to turn it off: viewers can stop asking for live
updates, sharers can refuse boosts.

### 10.4 Key storage at rest (question 5)

The existing `SecureStorage` is **plaintext `SharedPreferences`** (sandbox protection only), and on
desktop it writes into `settings.ini`. Not suitable on its own. The design (D6, approved with the
key rotation):

- **Wrapping key.** A non-exportable AES-256-GCM key in **Android Keystore** wraps a random 32-byte
  data key. The key is hardware-backed where available, with no user-authentication requirement,
  because sharing must work with the screen locked.
- **Data file.** The data key encrypts `live_location.dat` with XChaCha20-Poly1305 (§8.5).
- **Rotation.** Both keys are replaced whenever secrets in the file are erased. That happens about
  once a day (the ratchet), at every pairing and at every contact deletion. The old Keystore key is
  deleted once the new file is in place. Erasing a key in the file thus no longer depends on flash
  storage erasing the file's old blocks, which it does not do reliably.
- **Limits of the rotation.**
  - A deleted Keystore key is certainly gone only on devices whose Keystore is rollback-resistant.
    Elsewhere, the deleted key blob may survive on flash. Recovering an old data key would then take
    a raw flash image *and* code execution inside that same device's secure hardware, which is
    beyond the threat model.
  - Key material is handled in native code, which wipes it after use (`crypto_wipe`). Java only
    passes the wrapped data key through for unwrapping and zeroes its copy afterwards; it never sees
    chain or stream keys.
- **Locked devices (T7).** The file lives in credential-encrypted storage. Before the first unlock
  after a reboot, it cannot be read, and the app does not run. After the first unlock, Android keeps
  the storage keys in memory even while the screen is locked, and the Keystore key works then too,
  because sharing must continue. A forensic exploit of a device in that state gets what the app
  holds at that moment, but nothing from before its ratchet and erasure.
- **Backups.** The file lives in `noBackupFilesDir`, so it is excluded from every backup without
  touching the backup rules. A restored backup therefore has no live-location state: re-pairing is
  required, and key backup is out of scope.
- **Limitation.** None of this protects against code running as the app or as root (T8).

## 11. UX flows

### 11.1 Turning it on

Settings → Experimental → "Live location sharing" → the explanation screen (§11.6) is shown once →
"Live location" appears in the main menu.

### 11.2 Adding a contact (target: under a minute)

1. A: Live location → **Add contact**. A sees:
   - a QR code;
   - a "Share link" button that opens the share sheet with the `comaps://live/pair#…` link;
   - a countdown (10 min for QR, 24 h for a link);
   - "Waiting…".
2. B scans the QR with any camera or QR app that opens links, or taps the link, or uses **Paste
   invite** on the same screen. The stock cameras of three test phones all opened CoMaps (D8). If
   the invite uses relays that are neither B's nor the defaults, B is asked first (relay consent):
   "This invite uses relay.example.org, which isn't one of yours. Its operator would see your
   internet address while you connect." B sees "Connecting…".
3. With both apps open, within seconds (three relay round-trips), B sees "Check that the other phone
   shows **294 805**" → [Codes match] / [They differ]. B does not know A's name yet; it arrives
   with A's confirmation. "They differ" stops the pairing on B's side and tells B not to connect.
4. A sees the joiner's name and the code. In person (QR): "Bob wants to connect. Check that Bob's
   screen shows **294 805**" → [Codes match, connect] / [Decline]. By link: "Bob wants to connect.
   Code **294 805**: compare it with Bob, by phone or in person" → [Codes match, connect] /
   [Connect without comparing] / [Decline].
5. B: "Connected with Alice". B's app sends its confirmation (spec §6.3), and A's contact changes
   from "Waiting for Bob to finish connecting" to connected when it arrives. If it never arrives
   (Bob came back after the invite expired, refused the code, or aborted), A's app says "Bob didn't
   finish connecting" and offers to remove the contact.

**Verified, unverified and flagged.**

- Each app marks a contact **verified** only when its own user has confirmed that the codes matched:
  at pairing time, or later in the contact details ("Compare code").
- Otherwise the contact is **unverified**, which is the normal outcome of a link pairing nobody
  checked. A reader of the link could have raced Bob, or a rewritten link could hide a man in the
  middle (T6, T6b); only comparing codes rules both out.
- A contact is **flagged** when someone else used the same invite after this pairing finished
  (spec §6.3). The app says: "Someone else also used the invite you connected with. Compare the
  code with Bob before you share your location." Comparing the codes verifies the contact and
  clears the flag; if they differ, the app offers to delete the contact.

The apps need not be open at the same moment. Each step waits on the relays until the invite
expires, and is taken when the app that owes it is next in the foreground. A link invite can
therefore complete over hours, but it may take up to four turns. The waiting screens say so:

- A, after sharing a link: "Bob can open this link within 24 hours. Connecting finishes once you
  have both opened CoMaps; it is quickest while you both have it open."
- B, waiting: "Waiting for the other phone. You can close CoMaps; connecting continues the next
  time you open it."

If a second device uses the same invite before the pairing ends, both apps stop: "Someone else used
this invite too, so it was cancelled. Make a new invite and share it only with the person you want to
connect with." The apps keep watching the invite until it expires, so this also catches an attempt
made while one of them was closed.

### 11.3 Sharing

Live location → **Share my location** → pick contacts (multi-select) and a duration (15 min, 1 h,
8 h, until I stop) → **Start**.

- Permission prompts: location (fine) if missing; notifications on API 33+.
- Notification: "Sharing live location with Bob and Carol · until 18:30" with **Stop**.
- On the map, an indicator chip shows "Sharing with 2". Tapping it opens **Manage sharing**:
  per-person stop, add people, extend, stop all.
- Extending or adding someone is only ever done by the sharer.
- Contacts in the picker show their status (D18). Unverified contacts carry a warning: "You haven't
  compared codes with Bob. If the link was intercepted, someone else could receive your location."
  Flagged contacts cannot be picked until their code has been compared, and contacts still waiting
  to finish connecting cannot be picked at all.

**No silent sharing.** Android does not guarantee that the notification is seen:

- On Android 13+, a foreground service keeps running when the app's notification permission is
  denied. Its notice then appears only in the system's Task Manager, not in the notification drawer.
- From Android 13 users can swipe a foreground-service notification away, and from Android 14 even
  one marked "ongoing".

Someone with brief access to the phone could otherwise start a share that its owner never sees.
So:

- Sharing does not start unless notifications are enabled for the app and the sharing channel is
  not blocked: `areNotificationsEnabled()`, channel importance not `IMPORTANCE_NONE`, channel group
  not blocked. The share sheet explains why and links to the setting.
- The service re-checks before every publish, and on the system's block-state broadcasts (API 28+).
  If notifications were turned off, it stops the share at once, exactly as "Stop all" would.
- If the notification is swiped away, its delete intent posts it again at once.
- There is no device-credential prompt before pairing or sharing (D15).

### 11.4 Viewing

- Contacts sharing with you appear as coloured dots with their name label, shown up to a contact
  limit.
- Each dot fades to grey when its update is over 2 minutes old ("last seen 7 min ago" on tap). It
  disappears when the share ends or `until` passes.
- When a stream ends, its dot stays, greyed, for up to 2 minutes, or until the sharer's next state
  says whether the share goes on. A share that the sharer re-keys (someone added or removed, a new
  day) therefore continues without the dot blinking out, even when the `end` arrives before the new
  grant.
- Tapping a dot opens a small sheet: name, last update, accuracy, "Center", "Hide". Hide stops
  every connection made for that contact (its stream, its signals), not just the dot.
- **Relay consent.** The app connects for a contact only to relays that are the user's own, the
  defaults, or approved. When a contact's share comes through a relay outside these, the app asks
  once before connecting: "Bob's location comes through relay.example.org, which isn't one of yours.
  Its operator would see your internet address whenever you view Bob." The same applies when
  sending a contact states, e.g. when the user stops sharing with it (T5b).
- With D4, opening the map makes the sharer's dot go live within a few seconds. In the worst case
  (the sharer's listening relay died silently), it takes until the sharer's next heartbeat.
- Positions are kept in memory only. Opening the app fetches each contact's latest position from
  the relays again.

### 11.5 Contacts and settings

- Contact list: name, status ("Sharing with you until 18:30", "You share until …"), a verified /
  unverified / flagged badge, rename, compare code, delete. Deleting a contact also stops any share
  with them.
- Relays: list, add, remove, reorder (the first reachable one is the listening relay, D17), and a
  reachability test. Only `wss://` addresses are accepted. A warning appears when fewer than two
  relays work. A second list, "Relays you allowed for contacts", shows the approvals given under
  relay consent, each with the contact that asked for it, and lets the user revoke them.
- Toggles: "Request live updates when viewing" and "Allow viewers to request live updates" (D4),
  and the low-battery stop threshold.

### 11.6 What relays can see (one screen)

Draft text, also a DoD item. It now claims only what the threat model supports (§3):

> **How live location stays private**
>
> Your location is encrypted on your phone. Only the people you choose can decrypt it.
>
> It travels through relays: independent servers run by volunteers or companies (you can pick
> your own). Relays **cannot** see your location, your name or your contacts' names.
>
> Relays **can** see:
>
> - your phone's internet address, which reveals your rough region and your provider;
> - the internet addresses of the phones that follow your location, so a relay could tell which
>   phones you share with, though not whose they are;
> - when you send updates and how often (moving phones send more often, and so do phones that
>   someone is watching);
> - that the app uses this live-location feature, and roughly how many contacts you have.
>
> Your contacts may use relays other than yours. Before your phone connects to one of those, the app
> asks you, because whoever runs it would see your internet address.
>
> Relays that follow the rules keep only your latest encrypted position, and delete it 15 minutes
> after it was sent. A relay that breaks the rules, or anyone else, could keep copies. They stay
> encrypted, and the phones delete the keys that could open them within about a day.
>
> Your location is never sent while you are not sharing. While the app is open and you have
> contacts, it asks the relays whether anyone is sharing with you. People you stop sharing with
> cannot read anything you send afterwards.

## 12. Test plan

- **Unit (C++, `live_location_tests`)**:
  - every primitive against its published vectors: NIST SHA-256, RFC 5869, NIP-44 v2, BIP-340, and
    the Noise cacophony vector;
  - every NLL vector reproduced byte for byte from `nll1_vectors.json`;
  - the receiving rules, including tampering, replay, expiry, wrong key and oversize;
  - the pairing rules: one message per step on each side; conflicts watched until expiry, aborting
    before the end of the pairing and flagging after; forged, junk and misdirected steps; a
    low-order Noise key; a code that does not change with the payloads (the Python tests already
    cover these, as asynchronous scenarios over a model relay);
  - the receiving rules: silent discard of everything malformed, the JSON profile and the field
    checks, strict base64, with the negative cases of `test_protocol.py` ported;
  - the viewer keeping a stale position when an `end` arrives before the new grant;
  - revocation looking exactly like a stop to the removed recipient, and the 30–120 s silence;
  - the ratchet, epoch boundaries and clock skew; erasure of the pairing roots, chain keys and
    stream keys at both ends;
  - one epoch per connection, and decoy-padded inbox filters;
  - store round-trip, and data-key rotation on erasure;
  - the cadence and connection policy.
- **Integration (C++)**:
  - manager + relay pool against an in-process fake relay: 2 of 3 relays down, reconnect, duplicate
    and out-of-order delivery, replayed grants;
  - pairing and revocation end to end;
  - `LiveLocationMarks` against a stub, because `map_tests` is not run in upstream CI.
- **Cross-implementation.** A C++ desktop CLI and the Python reference interoperate over a local
  strfry (pair, share, revoke). The Python **test peer** (`peer.py`) pairs with a phone through a
  real invite link. It shows the phone's location and then proves it **cannot** decrypt after
  revocation: it keeps querying the old and the new stream key and logs failures.
- **Android (JVM)**: Robolectric/JUnit for the Java transport and the Keystore wrapper (mocked).
- **On device (you)**: a scripted checklist for the DoD.
  - the stock camera opens a `comaps://` QR code (D8, before anything else);
  - pairing time (stopwatch);
  - follow latency (screen recording of both phones, or a timestamp overlay);
  - stop and revocation (test peer);
  - time-limited end;
  - no silent sharing: with notifications denied or the channel blocked, sharing refuses to start;
    turning them off mid-share stops it; swiping the notification away brings it back;
  - two of three relays down (configure two dead hostnames);
  - no traffic when unused (PCAPdroid, FOSS, no root; or `dumpsys netstats` per UID);
  - without Play services (de-Googled device or Play services disabled);
  - one hour of battery and data: `dumpsys batterystats --reset` → 1 h → `dumpsys batterystats`
    and `netstats` for the UID.

## 13. Risks

| Risk | Mitigation |
|---|---|
| Relay policies tighten (web-of-trust, paid, kind whitelists are spreading) | Configurable relays, health checks, documented self-hosting; the soak harness re-runs in minutes |
| Doze and OEM battery savers stall network for a stationary sharer with the screen off | Measure on your devices. If needed, a user-initiated battery-optimisation exemption (F-Droid-safe) and an explanation |
| Metadata expectations (users may assume anonymity) | The one-screen explanation; Tor or proxy later |
| Clock skew (epochs, expiry) | ±1 epoch acceptance, 300 s future skew; phones are NTP-synced |
| Composition bugs in our protocol (not in primitives) | Independent reference implementation plus vectors, receiving rules tested adversarially; external review before any upstream proposal |
| Hook conflicts on rebase (`MwmActivity` is large and busy) | Hooks kept one-liners delegating to new classes |
| Kind numbers unregistered | Easy to change before release; propose a NIP later |
| libsecp256k1 internal-header shim on upgrades | Pinned version; vectors catch breakage; fallback is to vendor Bitcoin Core's `sha256.cpp` |
| Stalkerware misuse | No silent mode, enforced: no share without a visible notification, re-posted if dismissed (§11.3). Sharer-only control, no remote start or extend. D15 would add a credential prompt |
| A contact runs one of your relays | It sees that relay's metadata, also after you remove them from a share (T4). The relay screen and the self-hosting notes say so |
| A phone that stays off or unused keeps old chain keys | D16: a daily local ratchet |

## 14. Decisions

You signed off D1–D14 on 2026-10-10 (D8 after your camera test), and D15–D18 on 2026-10-11.

| # | Decision | Choice | Status |
|---|---|---|---|
| **D1** | Transport | **Nostr relays** (§6.1). Later, perhaps SimpleX SMP as a second transport | Approved |
| **D2** | Protocol structure | **No identity keys; Noise pairing; daily-ratcheted pairwise channels; sender-key stream rotated on every membership change** (§4, §5) | Approved, with the review fixes written into the spec (§16) |
| **D3** | What relays keep | **Latest position only (addressable, 15-min expiry)**, so a viewer sees the position as soon as it opens the map | Approved |
| **D4** | Update policy | **Viewer-driven live mode** (§10.3): every fix while watched, ≥ 50 m / 5 min otherwise; toggles on both sides | Approved; D17 refines its connections |
| D5 | Default relays | **nos.lol, nostr.mom, relay.nostr.net** (§6.3). Your note: for a small private circle, two self-hosted relays on different hosts cut third-party operators out entirely. The relay settings and the docs will say so, together with the caveat in §6.3 | Approved |
| D6 | Feature minimum Android, key storage | **API 24+; Keystore-wrapped data key; file in `noBackupFilesDir`** | Approved, with key rotation on erasure (§8.5, §10.4) |
| D7 | WebSocket library | **OkHttp 4.12** | Approved |
| D8 | QR scanning | **No in-app scanner**: the system camera or a QR app opens the link, plus "Paste invite" | Approved: the stock cameras of three phones opened CoMaps from the test QR. The invite has since grown from 91 to 123 bytes (the inviter's pairing key), so its QR code goes from version 8 to 10 (49 → 57 modules a side, still well within what phone cameras read). A re-scan of the new image is optional |
| D9 | SHA-256 source | **Shim over libsecp256k1's internal implementation** | Approved. Later, as a separate change: once CoMaps has Boost ≥ 1.88, switch to `boost::hash2::sha2_256` and `hmac_sha2_256` and delete the shim |
| D10 | Names | **Protocol "NLL v1", labels `nll1:`, kinds 30484/20484, link `comaps://live/pair#…`** | Approved |
| **D11** | When a viewer connects | **While the app is in the foreground and at least one contact exists**, to discover shares. Never in the background | Approved |
| D12 | Location payload | **lat, lon, acc, ts, spd, brg, alt; `low` battery flag; `nav` reserved** (PoC fields) | Approved |
| D13 | Pairing confirmation | **The inviter always confirms, with the code shown** | Approved |
| D14 | Strings | **A new English-only `strings_live_location.xml`**, translated later through the normal pipeline | Approved |
| D15 | Device credential before pairing, and before starting or extending a share | **None in v1.** The enforced notification (§11.3) makes every share visible, and a PIN does not stop someone who knows it | Approved |
| D16 | Ratchet while the app is idle | **A WorkManager job about once a day** (already a dependency) while live-location contacts exist. It advances the chain keys and rotates the storage keys, and sends nothing. "About": Android defers the background jobs of rarely used apps, so the interval can stretch beyond a day | Approved |
| **D17** | Connections while a share is unwatched | **One listening connection**, to the first reachable relay in the user's list; the others are connected only to publish (§10.3). Alternative: keep every home relay connected for the whole share. That costs about 1–1.5 %/h more on LTE for a stationary sharer, but live mode would still start promptly if the listening relay died silently (with one connection, it can take up to one 5-minute heartbeat) | Approved |
| **D18** | Unverified and flagged contacts | **Unverified contacts can receive shares, with a warning in the share sheet; flagged contacts cannot until their code has been compared** (§11.2, §11.3). A flag means someone else demonstrably used the invite, and the user cannot tell which of the two became the contact. Unverified is the normal state of a link pairing; blocking it would push people to tap "Codes match" without comparing. Alternatives: block unverified contacts too, or only warn for flagged ones | Approved |

## 15. Answers to the Phase 1 questions

### Q1. Do public relays accept this traffic?

Yes. Without AUTH, PoW or payment, mainstream relays accept and forward both addressable and
ephemeral events from fresh keys. NIP-40 is honoured by the recommended ones, and NIP-09 too,
though we avoid it. No rate limits were hit at the rates we need. See §6.3.

### Q2. Is there an existing NIP or design to adopt?

None fits; see §6.2. NLL reuses NIP-01, 40 and 44 plus Noise, and is small enough to propose as a NIP
later.

### Q3. Fan-out at 1, 10 and 50 recipients

Sender keys win: one event per update at any size. See §7.

### Q4. WebSocket library and minimum Android version

OkHttp 4.12, and API 24 for the feature. See §9 and §10.1.

### Q5. Key storage at rest

The existing SecureStorage is plaintext. Use a Keystore-wrapped data key with the file in
`noBackupFilesDir`. See §10.4.

### Q6. Update rate, battery and data

Viewer-driven live mode with idle heartbeats; budgets in §10.3, to be measured on device.

### Q7. CoMaps PoC (PR #2269)

The PR is "WIP: Live Location Sharing" by zyphlar, still open. Its description calls it a vibe-coded
proof of concept awaiting line-by-line review. Its branch is `zy-live-location`: 5 commits,
Oct 2025.

Its model:

- a central Node/SQLite server (`live.comaps.app`) and a **capability URL**
  (`sessionId:key` in a link) viewable in a browser;
- AES-256-GCM through OpenSSL in core, with iOS and Windows placeholders;
- a 20 s update interval, battery auto-stop below 10 %, and a navigation mode (ETA, distance,
  destination);
- a server that **stores location history** (a `location_updates` table and a `/history`
  endpoint) and keeps sessions for a week after they end.

Discussion:

- Maintainer review (x7z4w) asks to move crypto and networking logic into core, reuse core HTTP and
  framework logic, honour the low-battery setting, and floats WolfSSL. That last is GPL, which would
  break the Apache-2.0 compatibility you require.
- A commenter flagged that live.comaps.app is public and indexed before the PR is merged.

Reused here:

- **Payload fields**: speed, bearing, accuracy, battery, and a reserved `nav` object for future
  trip sharing.
- **UX patterns**: the foreground service and notification with Stop, the map indicator, the
  low-battery stop, and settings for interval and relays.

Not reused:

- the server, history storage and capability URLs, which conflict with requirements 3–5;
- OpenSSL in core.

### Q8. Anything wrong in the brief, or a better approach?

- **"Ephemeral events are not stored"** is not quite true. strfry and others keep them for minutes
  and serve them to later queries. That is why NLL encrypts everything the same way and treats
  signals as briefly retained.
- **NIP-09 deletion** is counter-productive for minimal retention: the deletion request is kept
  forever. NLL uses latest-only replacement plus expiry instead.
- **Marmot/MLS** does not help a single-sender broadcast. Its onboarding is identity-bound, which
  conflicts with requirement 3. Sender keys plus Noise pairing give revocation with far less code.
- **The existing `SecureStorage` is not encrypted** on Android, contrary to its name.
- I found no materially better transport for v1. SimpleX's queue model has stronger metadata
  privacy and is worth a later look as a second transport.

## 16. Review changes (2026-10-10)

Your review of the 2026-10-09 draft, point by point. Every protocol change is in the spec, the
reference implementation, its tests and the regenerated vectors (200 primitive checks and 159
protocol checks pass).

| Your point | Verdict | What changed | Where |
|---|---|---|---|
| 1. Pairing needs a single-use rule on the joiner's side | **Right.** It also exposed a second hole of the same kind. The code came from the handshake hash, which covers the step 2 payload, so a man in the middle could vary that payload (any byte, since unknown JSON members are ignored) until the inviter's code matched the joiner's. That takes no key work at all, so the commitment did not help against it | Each side accepts exactly one message per step and aborts on a second, different one. The joiner answers one step 1 and sends step 2 at most once. The code now comes from the `Split()` keys, which depend only on the PSK and the two ephemeral keys. Tests: the joiner aborts on a second step 1, both before and after answering; the inviter aborts on a second step 0 or step 2; the code is unchanged by payloads while the hash is not | spec §6.3–6.4; T6; `test_protocol.py` |
| 2. Revocation reveals that the share continues | **Right.** A related leak: the stream's expiry was capped at the largest `until`, which told every recipient whether someone else's access lasted longer than its own | `end` has no reason. At a change the sharer publishes all states first (new grants, share-less states, in random order), then the `end`. The new stream is silent for a random 30–120 s. Stopping altogether has the same shape. The expiry cap is gone. T4 now states what traffic analysis can still show. A test checks that "remove Carol" and "stop sharing" look identical on the wire and to Carol | spec §9; T4; §4.4 |
| 3. Forward-secrecy gaps | **Right on all counts.** Also, the reference implementation never ratcheted its stored key: it derived later keys but kept the old one. And a phone that does not run keeps old keys, which became D16 | The roots `k1`/`k2` are erased once the first chain key is derived. Recipients erase stream keys on replacement, end or `until`. Both keys protecting the store rotate on every erasure. No positions or stream keys are ever written to disk. `Direction.advance()` really ratchets, and tests check that erased epochs cannot be re-derived | spec §6.3, §7, §12, §13; §8.5, §10.4 |
| 4. "No silent mode" isn't enforced | **Right.** There is a second path: Android 13 lets users swipe a foreground-service notification away, and Android 14 even an "ongoing" one | Sharing refuses to start, and stops, unless notifications are enabled and the channel isn't blocked. A dismissed notification is posted again. Device-credential confirmation is offered as D15 (I recommend against) | §11.3; §2; D15 |
| 5. The claims overclaim | **Right on all four** | The filter linkage is now fixed, not just documented: one epoch per connection, and the inbox list padded with decoys to a multiple of 8. One author list now covers states and signals, so relays cannot tell recipients from other contacts. T1, T7 and the one-screen text now claim only what holds | spec §11; T1, T7; §11.6 |
| 6. D4's own cost is missing | **Right** | Connections are counted in the model; one listening connection while unwatched (D17) | §10.3; D17 |
| 7. strfry pings every 55 s | **Right in substance, one detail differs.** Measured over 10 minutes: nos.lol and nostr.mom, both strfry, ping every **240 s** (so not strfry's default); relay.nostr.net pings every 55 s. Three idle connections still wake the radio about 95 times an hour | The revised estimates use the measured intervals | §6.3, §10.3; `results/2026-10-10_round4_keepalive_10min.json` |
| Move the inviter's name to step 3 | **Done.** Step 1 now carries nothing; the inviter's name, relays and pairing epoch travel in step 3 under a key derived from `ee` | | spec §6.3; T6 |
| "Pairing requires both apps to be open at the same time" | **Not quite.** Every step is stored on the relays until the invite expires, so the apps can take turns. That can take up to four turns, though, so the UI says it is quickest with both apps open | Waiting-screen texts | §11.2; spec §6.1 |
| `wss://` only | **Done.** `ws://` is accepted only for `localhost`, `127.0.0.1` and `[::1]` (local test relays); senders and receivers enforce it | | spec §5 |
| D5, D8, D9 notes | Recorded | Self-hosting note with its caveat; a QR test image for D8; the Boost.Hash2 path for D9 | §14, §6.3 |

## 17. Second review changes (2026-10-11)

Your second review, point by point. I reproduced all six findings on the reviewed commit (646af0bb)
before changing anything, and each one is now a regression test. 200 primitive checks and 224
protocol checks pass, and the vectors are regenerated.

| Your point | Verdict | What changed | Where |
|---|---|---|---|
| 1. Asynchronous pairing lets anyone holding the invite impersonate either side | **Right**; reproduced as you describe it. One correction to the suggested fix: a regular kind alone would not have closed it. All four steps were signed by one key derived from the PSK, and NIP-09 tells relays to delete any event whose pubkey matches a deletion request's. The default relays honour that (§6.3, round 1), so Mallory could have deleted Alice's step 1 instead of replacing it | **No shared signing key.** The invite carries the inviter's one-time pairing key, which signs steps 1 and 3. Joiners sign steps 0 and 2 with fresh keys of their own, prove with a MAC in step 0 that they hold the invite, and tag the inviter's key so that the inviter finds them. Nobody can sign as the inviter, nor replace or delete anyone's events. Impersonating the inviter is therefore impossible, and a racing joiner stays visible. Both sides watch until the invite expires: they abort if a conflict comes before the pairing ends, and flag the contact if it comes after. A flagged contact gets no share until its code has been compared (D18). Contacts start unverified, and the joiner can now confirm the codes too. The prologue binds the step 0 being answered, so a joiner sees at once when the inviter answered someone else. The kind stays 30484; the relay probe ran on the new layout (round 5) | spec §6; T6, T6b; §4.1, §11.2, §11.3 |
| 2. `extend()` adds a recipient without a new stream | **Right** | `extend()` accepts only current recipients and a future `until`; additions go through `change()` | `protocol.py` (spec §9 already required it) |
| 3. An `end` that arrives before the new grant blanks the map | **Right** | Your suggested fix, both parts. The viewer keeps the last position, stale, for up to 120 s or until a state decides. The sharer waits for an `OK` on each state (up to 10 s) before the `end`; `Sharer` now returns the states and the `end` separately. Tests cover "remove one" and "stop all" with the `end` arriving first, and the expiry of the grace period | spec §9, §12; §11.4 |
| 4. Pairing just before midnight breaks the joiner | **Right** | Your fix: `e_p = epoch(now − 300)`, and the joiner rejects `e_p > epoch(now)`. Also, `inbox_filters` now skips a contact whose chain is ahead of the clock instead of failing for every contact, and a chain ahead of the clock (after the clock was set back) still signs. Tested with the skew in both directions | spec §6.3 |
| 5. Receiving rules and consistency between implementations | **Right on all four.** More of the same kind turned up: Python counts `true` as an integer; `json.loads` turns `1e400` into infinity and accepts duplicate names and lone surrogates; the base64 decoder accepted non-canonical input; relay URLs were checked with a URL parser whose quirks another implementation would not share | Every read path discards silently. The spec now has: a field-check table for every message type; an I-JSON profile with an exact definition of an integer; strict, canonical base64 and lowercase hex; relay URLs as an explicit pattern; an abort on an all-zero `ee`; exact rules for `kind`, `created_at`, `expiration` and reading tags. Each rejection is tested for its reason, not just for a `None` | spec §2, §3, §5, §12 |
| 6. The joiner keeps the PSK and the rendezvous key | **Right**, and the inviter kept its rendezvous key as well | When the pairing ends, both sides erase the PSK, their pairing secret, the ephemeral key, the Noise state and the roots. Until the invite expires they keep only the MAC key and public data. Tested on both sides | spec §6.3, §13 |
| Decisions | D8 passed on three phones; D15: none in v1; D16: about daily; D17: one listening connection | Recorded. The invite grew to 123 bytes, so its QR code is now version 10 | §14 |

## 18. Third review changes (2026-10-11)

Your third review, point by point. All three findings reproduced on the reviewed commit (87577057),
and each is now a regression test. 200 primitive checks and 243 protocol checks pass, and the vectors
are regenerated. The pairing values are unchanged; the joiner's confirmation state is new.

| Your point | Verdict | What changed | Where |
|---|---|---|---|
| 1. Contacts choose which relays your phone connects to | **Right**; reproduced: a ten-year invite pointing at `wss://stalker-relay.example` was accepted. One extension: the same exposure exists when *publishing* to a contact's inbox relays. When you stop sharing with someone, your phone delivers a share-less state to their relays. A removed recipient running its own inbox relay would therefore learn your IP address at the moment you removed it | Relay consent covers reading, publishing, signals and pairing. Without asking, the phone uses only its own relays, the defaults and approved relays; for any other relay there is one prompt, naming the contact. An unapproved relay is skipped, which costs revocation nothing because it is cryptographic. Hide stops every connection for the contact. Invites live at most 24 hours: the inviter cannot make a longer one, and a joiner refuses one more than a day plus the skew ahead. New threat-model row T5b and residual-leak entry | spec §6.1, §11, §13; T5b; §11.2, §11.4, §11.5 |
| 2. Pairing can complete on one side only | **Right**; reproduced: `decide()` worked even after expiry, and the late joiner ignored the expired step 3 | Your fix. Right after accepting step 3, the joiner publishes one share-less state on the new channel. The inviter's contact shows as "waiting" until a state arrives, and the app offers to remove it. `decide()` refuses after expiry, and also after an abort, which used to crash. §13 lists the one exception. The confirmation state is in the vectors | spec §6.3, §8, §13; §11.2, §11.3 |
| 3. A low-order key in step 1 bypasses the joiner's abort | **Right**; reproduced: a plain `ValueError`, with step 1 recorded and nothing erased | Writing step 2 now happens inside the guarded block. A joiner-side test checks the abort, that no step 2 is sent, and that everything is erased. I also checked every other step for errors escaping the abort path and found none left. In addition, an aborted joiner can no longer make a step 0 | `protocol.py`; tests |
| §2 still said "No `p` or `g` tags" | **Right** | It now says that the only `p` tag points at the invite's one-time pairing key | §2 |
| D18 | Approved | Recorded | §14 |

