# Live location sharing: design

Status: **approved for implementation**, after five review rounds:

- 2026-10-10: D1–D14 approved with a list of fixes, which §16 maps to their changes.
- 2026-10-11: D15–D17 approved; the requested changes are mapped in §17.
- 2026-10-11: D18 approved; the requested changes are mapped in §18.
- 2026-10-11: one more fix, to the pairing confirmation, mapped in §19.
- 2026-10-11: relay consent and the listening relay, mapped in §20.

All decisions are made ([§14](#14-decisions)). Phase 2 implemented them: [§22](#22-phase-2-report)
reports on it, [§21](#21-implementation-notes-phase-2) lists what the code decided where this
document left a choice, and [LIVE_LOCATION_DEVICE_TESTS.md](LIVE_LOCATION_DEVICE_TESTS.md) is the
checklist for phones.

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
19. [Fourth review changes (2026-10-11)](#19-fourth-review-changes-2026-10-11)
20. [Fifth review changes (2026-10-11)](#20-fifth-review-changes-2026-10-11)
21. [Implementation notes (Phase 2)](#21-implementation-notes-phase-2)
22. [Phase 2 report](#22-phase-2-report)
23. [Review of Phase 2 (2026-10-13)](#23-review-of-phase-2-2026-10-13)
24. [Second review of Phase 2 (2026-10-15)](#24-second-review-of-phase-2-2026-10-15)
25. [Third review of Phase 2 (2026-10-21)](#25-third-review-of-phase-2-2026-10-21)
26. [Fourth review of Phase 2 (2026-10-22)](#26-fourth-review-of-phase-2-2026-10-22)
27. [Fifth review of Phase 2 (2026-10-22)](#27-fifth-review-of-phase-2-2026-10-22)
28. [Sixth review of Phase 2 (2026-10-23)](#28-sixth-review-of-phase-2-2026-10-23)

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
| 1 | Consent and visibility | Off by default behind a feature flag. Sharing starts only from Manage sharing, with explicit recipients and duration. A foreground-service notification (with Stop) and an in-app indicator are shown while sharing. No silent mode exists: sharing refuses to start, and stops, while notifications for the app or its sharing channel are off, and a dismissed notification comes straight back (§11.3). Recipients have no message that could start, extend or alter a share; the protocol has no such message type at all. |
| 2 | Recipient control | Per-recipient `until`, Stop per recipient or all. Every membership change rotates the stream, so revocation is cryptographic and immediate (§4.4). |
| 3 | Confidentiality incl. metadata | No identity keys. Event keys are pseudonyms rotated per invite, per day or per stream, and no connection spans two days. The only `p` tag points at the invite's one-time pairing key, and there are no `g` tags. Payloads are padded per class, and inbox subscriptions are padded with decoys. What remains (IP addresses, timing, volume, keys used together within a day) is analysed in [§3](#3-threat-model). |
| 4 | Decentralisation | No server of ours. Any NIP-01 relay works. Publishing goes to all (default 3) relays, and the list is user-configurable, including self-hosted relays. Measured in [§6](#6-transport-evaluation-and-relay-test-results). |
| 5 | Minimal retention | Addressable "latest only" events with NIP-40 expiry: 15 min for positions, end of day + 1 h for channel state. No NIP-09 deletion requests, because relays keep those forever (§6.3). Viewers keep only the latest position per contact, in memory. Both ends erase keys, so copies of the ciphertext stay unreadable (§8.5). |
| 6 | Inert unless used | No initialisation without the flag. No connection without a paired contact. Then connections only while sharing, while pairing, or while the app is in the foreground and has contacts (decision D11). An unwatched share holds one connection (D17). For a week after joining someone's invite, the app also sends that contact one state on each day it runs (spec §6.3). The only background work without a share is a local daily ratchet that sends nothing (D16). |
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
| T5b | **A malicious contact as sharer, inviter or recipient** (for example a stalker you paired with) | **Choose the relays your phone connects to for it**: its stream relays when you view its share or send watch signals, its invite's relays while you pair and until the invite expires, its inbox relays when you send it states (also when you stop sharing with it, and on each day your app runs in the first week after you joined its invite). If it runs one of them, it learns your IP address, hence your rough location and provider, and when your app talks to it, e.g. when your map is open. You never have to share with it for this to happen. Mitigations: relay consent (spec §11): without asking, your phone uses only your own relays, the defaults and relays you approved; for any other relay a contact names, the app asks once, naming the contact and the relay. Invites live at most 24 hours. "Hide" stops all connections for that contact. | Make your phone connect to a relay you did not approve. Keep you watching an invite for more than a day. Learn anything about you from relays that you and other contacts use, beyond what T1 says about every relay operator. |
| T6b | **Someone who rewrites an invite in transit** (substitutes its own) | **Sit in the middle** of both pairings. The protocol cannot see it: the two screens show different codes, matching by chance with probability 10⁻⁶. It cannot grind the codes: the joiner commits to its key first, each side accepts one message per step, and the code comes from the keys, not the transcript (spec §6.3–6.4). Only comparing codes reveals it. | Anything, once the users have compared codes. |
| T7 | **Device thief or forensic examiner** | **Before the first unlock after a reboot:** nothing; the app's files are in credential-encrypted storage. **After the first unlock, even with the screen locked:** Android keeps the storage keys in memory, and forensic tools target exactly this state. With an exploit that runs code on the device, an attacker gets what the app holds now: the current channel keys, and the latest positions while the app is running (in memory). A background job (D16) erases the stored chain keys that are due about once a day, even while the app is not used; if Android has deferred that job for days, as it does for rarely used apps, the stored keys are that old. | Past channel keys (ratchet) and past streams (erased at both ends), hence the content of archived ciphertext. No positions are stored on disk. The limits of key erasure on flash are in §10.4. |
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
   public key, an expiry and A's relays (122 bytes and a 182-character link with the default
   relays).
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
6. B's app confirms with a first, share-less state on the new channel. A state can be read only
   until 01:00 UTC the next day, and A's app might not run before then, so for the first week B's
   app sends its current state again on each UTC day it runs. Until one arrives, A's app shows B as
   "waiting": pairing is complete only when both sides hold the contact. "Waiting" is a label, not a
   block, and A's app offers to remove B only once that week is over.

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
A sharer that nobody watches listens on one relay only, the first in its list. The signal works
only if the viewer may use that relay; otherwise the viewer's app asks for it, and shows "Live
updates off" while it stays refused (§10.3, §11.4).

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
| `.gitmodules`, `3party/CMakeLists.txt` | add secp256k1 submodule + `add_subdirectory` | ~27 lines |
| `libs/CMakeLists.txt` | `add_subdirectory(live_location)` | 1 line |
| `libs/map/user_mark.hpp/.cpp` | `LIVE_LOCATION` enum value + `DebugPrint` case | 2 lines |
| `libs/map/CMakeLists.txt`, `libs/map/map_tests/CMakeLists.txt` | add `live_location_marks.*` and its test | 4 lines |
| `libs/map/bookmark_manager.cpp` | a tap finds the dots (`FindNearestUserMark`) | 1 line |
| `libs/map/framework.hpp/.cpp` | a tap on a dot goes to a listener, the app's sheet (§11.4); without one, as in the desktop app, a plain place page with the name | ~40 lines |
| `libs/drape_frontend/user_mark_shapes.cpp` | a mark's `needOverlay` goes in its own argument (§23) | 3 lines |
| `android/sdk/src/main/cpp/CMakeLists.txt` | JNI sources + link `live_location` | 1 line |
| `android/app|sdk/build.gradle.kts`, `gradle/libs.versions.toml` | OkHttp, qrcodegen | ~9 lines |
| `AndroidManifest.xml` | service, activity | ~16 lines |
| `MwmApplication` | start with the core; foreground and background; keep location while sharing | ~10 lines |
| `LocationHelper`, `BaseLocationProvider`, `AndroidNativeProvider`, `GoogleFusedLocationProvider` | a share alone in the background keeps location at its own pace (§10.3, §21) | ~65 lines |
| `MwmActivity` | "Share My Location" opens the feature while it is on (§11.1); the indicator's tap, and the compass below it; the dot's sheet closes where the place page does (back, `closeFloatingPanels()`, full screen); "Share Live Location" for the left button; the intent processor. `comaps://` already carries the ge0 short links (`comaps://<10 chars>/<name>`), so the invite processor goes before that handler. `live/pair#` cannot be a ge0 code: `/` and `#` are outside ge0's alphabet | ~70 lines |
| `maplayer/MapButtonsController`, `MapButtonsViewModel`, the ten `map_buttons_layout_*.xml`, `dimens.xml` | the sharing indicator, beside track recording's (§11.3); while a route is planned, both indicators clear of the header (`track_recorder_status_top_margin`) | ~165 lines |
| `prefs_main.xml` | the "Live location sharing" section of the settings (§11.1) | 8 lines |

### 8.4 Feature flag

A runtime preference "Live location sharing", default **off**, at the top of its own
section of the settings (§11.1). While off, nothing in the feature is constructed: no library init,
no threads, no files, no network. When it is switched off, all shares stop and connections close.
The one exception: the end of a share that it stopped, which no relay could be reached for then, still
goes out once there is a network, and once more on the next day (§29). Contacts are kept until deleted:
"Delete all live location data", in the same section, works while the feature is off too.

### 8.5 Persistence

One file, `live_location.dat`, in Android's `noBackupFilesDir`.

What it holds:

- contacts: name, relays, the chain key of each direction (for the oldest epoch still needed only),
  and sequence counters; whether a relay has accepted the latest state sent to each, and whether the
  end of a share is still to be sent once more on a later day (spec §8);
- the decoy seed (spec §11);
- pending pairings: until they end, the PSK, the pairing secret, the Noise ephemeral key and the
  step 0, and the steps no relay has accepted yet; until the invite expires, what watching for
  conflicts needs: the MAC key, the inviter's pairing key and the ids of the accepted events (spec
  §6.3);
- deleted contacts that have not been told yet that a share with them ended: their relays and states
  without a share made when they were deleted, one per UTC day, for 7 days at most. Not their keys,
  which go with them (spec §8, §29);
- each contact's verified and flagged status;
- the active share's settings (recipients and their `until`), so that the app can offer to resume
  after its process was killed.

What it never holds:

- positions, on either side. Viewers keep the latest position per contact in memory, and fetch it
  again from the relays when they start;
- stream secrets and stream keys. They live in memory only. After a process death, the sharer starts
  a new stream once the user resumes, and recipients re-read their grants from the relays: each
  contact's latest state, read once more (spec §8).

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
| **Idle** | nobody watching | when moved ≥ max(20 m, the two fixes' accuracies added), or the fix is at least twice as accurate (≥ 30 s apart); else heartbeat every 5 min | 30 s, balanced |
| **Ending** | user stops, `until` passes, battery down to the user's level (5 % unless changed, §11.3) | final `end` + states | stop |

- Viewers send `watch` every 60 s while the map is visible and the contact's share is active.
- Opening the map also immediately fetches the stored latest position. So "B sees A within ~5 s"
  holds from the first fix after B opens the map, end-to-end latency being p50 ≈ 0.25 s in the soak
  test.
- The idle heartbeat (5 min) keeps the 15-minute-expiring latest position alive on relays.
- Positions say `low` (spec §9) while the sharer's battery is at 15 % or below and the phone is not
  charging, Android's own threshold for a low battery; viewers show "Battery low".
- Idle publishing compares each fix with the last one published. Android reports accuracy as the
  radius that holds the true position with 68 % probability, and a phone lying still at balanced
  accuracy reports fixes that wander by about that much. A move counts only when it exceeds both
  accuracies added, so that the two circles do not overlap: with equal accuracies, about 10 % of a
  still phone's fixes pass, against 57 % if the larger accuracy alone were the bar. The 20 m floor
  keeps precise fixes from publishing every few steps. A fix at least twice as accurate as the one
  published is published too, so that a coarse position is corrected before the next heartbeat.

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

Viewers send each watch signal to every relay of the sharer's that they may use (relay consent,
§11.4). Live mode therefore needs the viewer to be allowed to use the sharer's listening relay, the
first in its list; its states carry the list in order. When the viewer may not use it, its app
asks for that relay, once, as it opens the share, saying that live updates need it. If the user
declines, the contact shows "Live updates off" and keeps the idle rate (§11.4). The sharer's order
stays as it is: moving a default relay to the top would override a user who put their own relay
first. If its listening relay fails, the sharer moves to the next one, which viewers reach if they
may use it. If the connection dies silently, the next heartbeat notices, so live mode then starts
up to one heartbeat (5 min) late, but it does start. OkHttp does not report the server's pings to
the app, so the list order, not a measured ping interval, picks the listening relay.

A relay can also keep the connection and accept posts, yet stop delivering them. So the listening
connection also subscribes to the share's own posts (spec §11): a relay passes each event it
accepts to every subscription that asks for it, the publisher's own included. On all eight relays
tested, the three defaults among them, each post came back at most 0.12 s after its `OK`; an exact
duplicate never does. A post accepted with `OK true` that has not come back 15 s later makes the
sharer listen on the next relay. The first is tried again after 5 minutes, alongside the one that
works, then after 10, 20, and at most every 30 minutes (±20 %), until a post comes back over it. A
relay that has never sent a post back is not judged. Such a relay is noticed 15 s after the next
post: within about 15 s while live, within one heartbeat while idle. It costs one more filter in the
subscription and one event down per post, while the radio is on for the post anyway.

Estimated budgets for one hour, sharer side, three relays, on LTE. They are estimates, and the
measurement the DoD requires replaces them. The model: a radio wake costs about 5–10 J (some 10 s at
0.5–1 W), GNSS draws about 0.05–0.1 W, and on a 15 Wh battery 1 %/h is 0.15 W. On Wi-Fi a wake costs
far less, and every idle case drops below 1 %/h.

| Scenario | Radio wakes per hour | Data | Battery |
|---|---|---|---|
| Constant 5 s cadence (no D4) | continuous | ≈ 2.5 MB up+down | **≈ 4–8 %/h** |
| D4, watched the whole hour | continuous | ≈ 2.5 MB | ≈ 4–8 %/h |
| D4, unwatched, walking (a publish every 30–90 s, by accuracy) | ≈ 50–135 | ≈ 0.2–0.6 MB | **≈ 1–3 %/h** |
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

Settings → **Live location sharing**, a section of its own, whose entry lists what is inside: "Name,
dot color, relays, live updates". At its top is the switch "Live location sharing", with the note
"When enabled, you'll find it in the main menu under Share My Location". Turning it on shows the
explanation (§11.6) once. Below the switch, "What relays can see" opens that explanation again, also
while the feature is off. Below Android 7 the entry is not listed (§10.1).

While the feature is on, **Share My Location** in the main menu opens its screen, under the same
title: "Send current location" (what the menu entry does otherwise: the system share sheet with a
link to the current position), "Share live location" (while sharing: "Stop sharing location", in
red), "Add contact", while sharing a row "Sharing with 2 people" that opens Manage sharing, open
invites, and the contacts.

Below "What relays can see", the section holds the settings (§11.5), one row each with an icon and
its value or an explanation below the title, as in the other sections. While the feature is off,
or its data cannot be read, they show their titles only, greyed: their values are in the encrypted
store, which only the running core reads, and a plain copy kept for display would put the user's
name and relays outside it. "Delete all live location data" stays usable.

### 11.2 Adding a contact (target: under a minute)

1. A: Share My Location → **Add contact**. A sees:
   - a QR code;
   - a "Share link" button that opens the share sheet with the `comaps://live/pair#…` link;
   - a countdown (10 min for QR, 24 h for a link);
   - "Waiting…".
2. B scans the QR with any camera or QR app that opens links, or taps the link, or uses **Paste
   invite** on the same screen. The stock cameras of three test phones all opened CoMaps (D8). A
   link opened from outside the app, a scanned QR code included, asks first: "Connect with whoever
   created this invite? They will see your name, Bob." → [Connect] / [Cancel]. The app cannot tell a
   scan from a tap, and a code on a poster is the same risk as a link. Opening a link must not by
   itself send B's name to whoever made it, nor add them as a contact, under whatever name they
   chose. If the invite uses relays that are neither B's nor the defaults, B is asked next (relay
   consent): "This invite uses relay.example.org, which isn't one of yours. Its operator would see
   your IP address while you connect." B sees "Connecting…".
3. With both apps open, within seconds (three relay round-trips), B sees "Check that the other phone
   shows **294 805**" → [Codes match] / [They differ]. B does not know A's name yet; it arrives
   with A's confirmation. "They differ" stops the pairing on B's side and tells B not to connect.
4. A sees the joiner's name and the code. In person (QR): "Bob wants to connect. Check that Bob's
   screen shows **294 805**" → [Codes match, connect] / [Decline]. By link: "Bob wants to connect.
   Code **294 805**: compare it with Bob, by phone or in person" → [Codes match, connect] /
   [Connect without comparing] / [Decline].
5. B: "Connected with Alice". B's app sends its confirmation (spec §6.3), and A's contact changes
   from "Waiting for Bob to finish connecting" to connected when it arrives. Each confirmation can
   be read only until 01:00 UTC the next day, so B's app repeats it on each UTC day it runs, for the
   first week. Meanwhile A can already share with Bob (§11.3). If nothing has arrived once that
   week is over (Bob came back after the invite expired, refused the code, aborted, or has not
   opened CoMaps since), A's app says "Nothing has arrived from Bob since you connected. Bob may not
   have finished connecting, or may not have opened CoMaps since." It offers to remove the contact,
   and keeping it is equally fine.

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

Leaving the screen while A's invite is still open asks "Leave the invite waiting?" → [Leave it
waiting] / [Cancel invite]. Share My Location lists an invite left waiting ("Invite waiting"), and
opening it returns to the screen.

If a second device uses the same invite before the pairing ends, both apps stop: "Someone else used
this invite too, so it was cancelled. Make a new invite and share it only with the person you want to
connect with." The apps keep watching the invite until it expires, so this also catches an attempt
made while one of them was closed.

### 11.3 Sharing

Share My Location → **Share live location** opens **Manage sharing**, the one screen for starting
a share and for changing it. Without contacts, Share My Location has no such button, and says "No
contacts yet. Add a contact to share your live location.":

- At the top, "Someone is watching: updates every few seconds" while a viewer watches.
- "Currently sharing with": those the user shares with, ticked, each with its end ("Until 18:30",
  "Until you stop"). Unticking one stops sharing with them at once.
- "Start sharing": first "For", then everyone else, unticked. "For" offers 15 min, 1 hour
  (preselected), 8 hours, until I stop, and "Until…", a time on a clock (tomorrow if it has passed
  today). Ticking a contact shares with them for that long. Contacts ticked within 2.5 s of each
  other are added in one change, and at the latest when the screen goes: each change of recipients
  re-keys the stream (spec §9), with up to two minutes of silence for those already following.
- "Stop all", in red, at the bottom.
- Permission prompts come with the first tick when nothing is shared yet: location (fine) if
  missing; notifications on API 33+.
- Notification: "Sharing live location with Bob and Carol · until 18:30" with **Stop**.
- On the map, a round indicator like track recording's sits at the top right, where track
  recording's does, or below it when both show; the compass moves below them. The number of people
  is cut out of the pin in its icon. It blinks between grey and blue, in step with track
  recording's grey and red. Tapping it opens Manage sharing. Stopping every share thus takes two
  taps. While a route is planned, both indicators sit below the planning header.
- The map's left button can be set to **Share Live Location** (Settings → Interface → Left button
  setup), which opens Manage sharing; with no contacts yet, Share My Location; with the feature off,
  its explanation.
- A contact's details (§11.5) say how long the user shares with them, with "Change" to set another
  end, earlier or later, and "Stop sharing with Bob".
- Extending or adding someone is only ever done by the sharer.
- Contacts in the picker show their status (D18). Unverified contacts carry a warning: "You haven't
  compared codes with Bob. If the link was intercepted, someone else could receive your location."
  Flagged contacts cannot be picked until their code has been compared. Contacts still waiting to
  finish connecting can be picked, with a label: "Bob may not have finished connecting, and may not
  receive this." If Bob never finished, nobody else holds the keys, so nothing leaks. A contact none
  of whose relays the user may use is labelled "Messages to Bob need relay.example.org", and ticking
  it asks the relay question (§11.4) first.
- The share stops when the battery runs down to the level set in Settings (5 % unless changed), but
  not when the user started it at or below that level: then it stops only after the battery has
  been above it. While the phone charges, it never stops for the battery.

**No silent sharing.** Android does not guarantee that the notification is seen:

- On Android 13+, a foreground service keeps running when the app's notification permission is
  denied. Its notice then appears only in the system's Task Manager, not in the notification drawer.
- From Android 13 users can swipe a foreground-service notification away, and from Android 14 even
  one marked "ongoing".

Someone with brief access to the phone could otherwise start a share that its owner never sees.
So:

- Sharing does not start unless notifications are enabled for the app and the sharing channel is
  not blocked: `areNotificationsEnabled()`, channel importance not `IMPORTANCE_NONE`, channel group
  not blocked. Manage sharing explains why and links to the setting.
- The service re-checks before every publish, and on the system's block-state broadcasts (API 28+).
  If notifications were turned off, it stops the share at once, exactly as "Stop all" would.
- If the notification is swiped away, its delete intent posts it again at once.
- There is no device-credential prompt before pairing or sharing (D15).

### 11.4 Viewing

- Contacts sharing with you appear as coloured dots with their name label, shown up to a contact
  limit. The colour is the one each sharer chose in their settings (one of CoMaps' bookmark colours
  without the greys, spec §8), or, when they chose none, one the viewer's app derives from the
  contact.
- Each dot fades to grey when its update is over 2 minutes old ("last seen 7 min ago" on tap). It
  disappears when the share ends or `until` passes.
- When a stream ends, its dot stays, greyed, for up to 2 minutes, or until the sharer's next state
  says whether the share goes on. A share that the sharer re-keys (someone added or removed, a new
  day) therefore continues without the dot blinking out, even when the `end` arrives before the new
  grant.
- Tapping a dot or its name opens a sheet over the map: name and status, last update, accuracy,
  "Battery low" while the sharer's battery is at 15 % or below and not charging, "Center", and
  "Contact details", which opens the contact's screen. "Hide on the map" is there (§11.5): it stops
  every connection made for that contact (its stream, its signals), not just the dot. The sheet's
  lines update in place as positions arrive. It behaves as the place page does: the map stays
  bright and can be moved and zoomed while it is open, the map buttons rise above it, and "Center"
  puts the contact in the part of the map above it, and stops the map following the user's own
  position, as going to a bookmark does. A drag down closes it, as do back, the main
  menu, the search bar on the map (after a search), planning a route and full screen; a place
  tapped on the map, or a search result's, takes its place. The search button leaves it open, as
  it leaves the place page.
- **Relay consent.** The app connects for a contact only to relays that are the user's own, the
  defaults, or approved. When a contact's share comes through a relay outside these, the app asks
  once before connecting: "Bob's location comes through relay.example.org, which isn't one of yours.
  Its operator would see your IP address whenever you view Bob." The same applies when
  sending a contact states, e.g. when the user stops sharing with it (T5b).
- **Live updates.** When that relay is the first in Bob's list, the one his app listens on while
  nobody watches (§10.3), the prompt says why it matters: "Live updates from Bob need
  relay.example.org, which isn't one of yours. Without it, Bob's position updates only after he
  moves, or every 5 minutes. Its operator would see your IP address whenever you view
  Bob." → [Allow] / [Not now] / [Don't allow]. "Not now" asks again the next time the relay is
  needed, at most once each time the app runs; "Don't allow" never asks again, and Settings lists
  the relay so that it can be allowed there. Until it is allowed, Bob's contact shows "Live updates
  off" (on his dot's sheet and in the contact list), and his position keeps the idle rate. His
  details say "Live updates from Bob need relay.example.org"; tapping that asks the question again.
  With "Request live updates when viewing" turned off, the prompt does not mention live updates,
  and no label appears.
- With D4, opening the map makes the sharer's dot go live within a few seconds. In the worst case
  (the sharer's listening relay died silently), it takes until the sharer's next heartbeat.
- Positions are kept in memory only. Opening the app fetches each contact's latest position from
  the relays again.

### 11.5 Contacts and settings

- Contact list: name, status ("Sharing their location with you until 18:30", "Sharing your
  location with them until …", "Waiting for Bob to finish connecting", "Unreachable until you allow
  a relay"), and a verified / unverified / flagged badge. A tap opens **Contact details**: rename (a
  tap on the name), the labels (a flag, the offer to remove, not moved, "Messages to Bob need …",
  "Live updates from Bob need …"; a tap on either of the last two asks the relay question again),
  how long the user shares with them ("Change"), last update, accuracy and a low battery, "Hide on
  the map" with what it does below the switch, "Show on the map" (which, as "Center" does, stops the
  map following the user's position), "Compare code", "Stop sharing with Bob" and "Delete contact".
  A new position updates its lines in place. Deleting a contact also stops any share with them.
- After the user changes their relays, a contact whose app has not yet answered through the new
  ones (spec §11) shows "Hasn't picked up your new relays yet". Its screen explains: "Bob hasn't
  picked up your new relays yet. Until then, CoMaps also checks your previous relays, for up to 30
  days after the change. Ask Bob to open CoMaps." After the 30 days the label reads "Hasn't picked
  up your new relays", and the screen warns that what Bob sends may not reach the user. A contact
  that never finished connecting is not labelled, and nobody waits for it: it is offered for
  removal instead (§11.2).
- The settings below are in Settings → Live location sharing (§11.1), in this order, each a row with
  an icon:
  - **Appear as**: the name contacts see when connecting.
  - **Color you appear as**: the colour of the user's dot on contacts' maps, from a grid of CoMaps'
    bookmark colours without the greys, or "Automatic" (the default), which leaves it to each
    contact's app.
  - **Relays** opens a dialog with the list in order (the first reachable one is the listening
    relay, D17), each to move up or remove, and "Add relay". When the first relay isn't a default
    one, a note says that contacts get live updates from you only if they use or allow that relay
    too. Only `wss://` addresses are accepted. A warning appears when the list has fewer than two.
  - **Relays for contacts** opens a dialog with the answers given under relay consent, each with the
    contact it was for: relays allowed, to revoke, and relays refused with "Don't allow", to allow.
  - **Request live updates when viewing** and **Allow viewers to request live updates** (D4),
    switches with what they do below their titles.
  - **Stop sharing at low battery**: Never, 5 (the default), 10, 15, 20 or 30 %.
  - **Delete all live location data**.

### 11.6 What relays can see (one screen)

The text, also a DoD item. It claims only what the threat model supports (§3):

> Your live location is always sent encrypted. Only the people you choose can decrypt it.
>
> It travels through relays: independent servers run by volunteers or companies (you can pick
> and run your own). Relays **cannot** see your location, your name or your contacts' names.
>
> Relays **can** see:
>
> - Your phone's IP address, which reveals your rough region and your network provider.
> - The IP addresses of the phones that follow your location, so a relay could tell which phones
>   you share with, but not who they belong to.
> - When you send updates and how often (phones send more often when moving, or when someone is
>   watching).
> - That the app uses this live location feature, and roughly how many contacts you have.
>
> Your contacts may use relays other than yours. Before your phone connects to one of those, the app
> asks you, because whoever runs it would see your IP address.
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
    low-order Noise key; a code that does not change with the payloads; the joiner's daily
    confirmations through epoch `e_p + 7`, and the moment removal is first offered (the Python tests
    already cover these, as asynchronous scenarios over a model relay);
  - the receiving rules: silent discard of everything malformed, the JSON profile and the field
    checks, strict base64, with the negative cases of `test_protocol.py` ported;
  - the viewer keeping a stale position when an `end` arrives before the new grant;
  - revocation looking exactly like a stop to the removed recipient, and the 30–120 s silence;
  - the ratchet, epoch boundaries and clock skew; erasure of the pairing roots, chain keys and
    stream keys at both ends;
  - one epoch per connection, and decoy-padded inbox filters;
  - store round-trip, and data-key rotation on erasure;
  - the cadence and connection policy, including a viewer that may not use the sharer's listening
    relay ("Live updates off").
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
| Doze and OEM battery savers stall network for a stationary sharer with the screen off | Stock Android lets an app with a foreground service, as a running share has, use the network in Doze (AOSP's `NetworkPolicyManager`); OEM savers may not. What could not be sent goes again once there is a network (§29). Measure on your devices. If needed, a user-initiated battery-optimisation exemption (F-Droid-safe) and an explanation |
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
| **D4** | Update policy | **Viewer-driven live mode** (§10.3): every fix while watched; otherwise a move beyond both fixes' accuracies (at least 20 m), or every 5 min; toggles on both sides | Approved; D17 refines its connections. The idle rule was ≥ 50 m until the second review of Phase 2 (§24) |
| D5 | Default relays | **nos.lol, nostr.mom, relay.nostr.net** (§6.3). Your note: for a small private circle, two self-hosted relays on different hosts cut third-party operators out entirely. The relay settings and the docs will say so, together with the caveat in §6.3 | Approved |
| D6 | Feature minimum Android, key storage | **API 24+; Keystore-wrapped data key; file in `noBackupFilesDir`** | Approved, with key rotation on erasure (§8.5, §10.4) |
| D7 | WebSocket library | **OkHttp 4.12** | Approved |
| D8 | QR scanning | **No in-app scanner**: the system camera or a QR app opens the link, plus "Paste invite" | Approved: the stock cameras of three phones opened CoMaps from the test QR. The invite has since grown by 32 bytes (the inviter's pairing key), from 90 to 122 with the default relays (from 91 to 123 in the test image, which encodes the vectors' example), so its QR code goes from version 8 to 10 (49 → 57 modules a side, still well within what phone cameras read). A re-scan of the new image is optional |
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
| Decisions | D8 passed on three phones; D15: none in v1; D16: about daily; D17: one listening connection | Recorded. The invite grew to 122 bytes with the default relays (123 in the vectors' example), so its QR code is now version 10 | §14 |

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

## 19. Fourth review changes (2026-10-11)

Your fourth review had one finding. It reproduced on the reviewed commit (cd71dd10), and your
scenario is now a regression test. 200 primitive checks and 279 protocol checks pass. The vectors
are unchanged: the fix adds no message, only a rule for when the joiner sends its state.

| Your point | Verdict | What changed | Where |
|---|---|---|---|
| 1. The joiner's confirmation can expire before the inviter sees it | **Right**; reproduced: Bob confirms at 23:30 UTC, the state expires at 01:00, and at 08:00 Alice's app finds nothing, so Bob stays "waiting". A longer expiry would not have helped: Alice's app erases that day's channel key at 01:00 anyway. One adjustment to your fix: what Bob sends each day is his *current* state, not a share-less one. Once Bob shares with Alice, a share-less state would end his share | Your fix. Through epoch `e_p + 7`, whenever Bob's app runs on a UTC day on which it has sent Alice no state, it sends its current state, with the grant while it shares with her; a share's own states count. Any message from Bob confirms him, a watch signal included. "Waiting" is a label in the share sheet, not a block. Removal is offered only once the last confirmation Bob owed has expired, at `epoch_end(e_p + 7) + 3600`, about 7 to 8 days after pairing, and the offer says that Bob may simply not have opened CoMaps. No long-lived key: the confirmation uses the daily channel keys like any state. Tests cover your scenario, the daily window, sharing with a waiting contact, a signal confirming, the grant in the re-sent state, and the exact moment removal is first offered | spec §6.3, §8, §10, §13, §14, §15; §2, T5b, §4.1, §11.2, §11.3, §11.5, §12 |

**What remains.** Each confirmation can be read from the moment Bob's app first runs on a UTC day
until 01:00 UTC the next day. If Bob only ever opens CoMaps late in the UTC day and Alice only
early, the week can pass without the two overlapping. Waiting no longer blocks anything, so all
this costs is the label and, after the week, the removal offer. Sharing narrows the gap if Bob's
app may use Alice's listening relay, the first in her list (corrected in §20): while she shares,
her app listens there (§10.3), so it hears Bob's next confirmation as it arrives, and a watch
signal, sent when Bob opens Alice's location, confirms him at once. If Bob hasn't allowed that
relay, his app asks for it when he opens her location (§11.4); until then, Alice's app reads his
confirmations only while it is open.

## 20. Fifth review changes (2026-10-11)

Your fifth review had one finding. I reproduced it on the reviewed commit (bbbecaef) with the
reference implementation and one model store per relay: with Alice's own relay first in her list
and Bob not allowed to use it, his watch signal reached only her other relay, and the relay she
listens on heard nothing. That scenario is now a test. 200 primitive checks and 284 protocol checks
pass; the vectors are unchanged.

| Your point | Verdict | What changed | Where |
|---|---|---|---|
| Relay consent and D17 interact: live mode never starts for a viewer who hasn't allowed the sharer's first relay, and Alice doesn't hear Bob's confirmations as they arrive while she shares, which §19 relied on | **Right**; reproduced as above. One extension: only the design doc said that the listening relay is the first in the list. The spec said neither that relay lists are ordered nor which relay a sharer listens on, so another implementation could not have known which relay to ask for | Your fix, in all three parts. §10.3 says that signals go only to the relays the viewer may use, and that live mode needs the sharer's listening relay; the sharer's order stays. The prompt for that relay says that live updates need it. If the user declines, the contact shows "Live updates off" and keeps the idle rate. Two small additions: tapping the label offers the relay again, since the app asks about each relay only once; and the relay settings note that contacts get live updates only if they use or allow a first relay that isn't a default. The spec now keeps relay lists in order, defines the listening relay, and requires the prompt and the label; `missing_listening_relay()` names the relay to ask for. §19 now says that sharing narrows its gap only when Bob may use Alice's listening relay | spec §8, §10, §11, §13, §15; §4.5, §10.3, §11.4, §11.5, §12, §19 |

## 21. Implementation notes (Phase 2)

The implementation (`libs/live_location`) follows this document and the spec. Where they leave a
choice open, it decided as below. Each is easy to change. The ones marked **review** change what
users or relays see and await your verdict; you ruled on the earlier ones in the second to fifth
reviews of Phase 2 (§24 to §27).

| Topic | What the code does | Why |
|---|---|---|
| Pairing connections | Each pairing has connections of its own, never shared with the inbox or with channel traffic. | Otherwise a relay could link the one-time pairing keys to the new contact's channel keys through a connection. It costs one connection per relay while a pairing runs in the foreground. |
| REQ ids | Random for every REQ. | A fixed id ("inbox") would link connections of different epochs. |
| Sharing in the background | The inbox stays on the listening relay alone even while live. | Viewers send signals to every relay they may use, so one is enough. The other relays are connected anyway while live, because positions are published every few seconds. |
| Yesterday's states | In the first hour of a day, an app in the foreground reads its contacts' states once (30 s) with yesterday's keys, over yesterday's scope. | A contact's latest state may still be signed with yesterday's key until it expires at 01:00. Holding a second subscription for the whole hour would cost more for little gain. |
| "Each UTC day it runs" | The joiner sends its daily confirmation when the app is in the foreground or sharing. | It never opens a connection just to confirm, which keeps "no traffic when unused" true. |
| Failing relays | A relay that refuses, drops the connection, sends no OK within 10 s (25 s while connecting), or leaves a REQ without EOSE for 15 s backs off: 1 s, doubling to 5 min, ±20 %. The back-off starts over once the relay answers a publish or a REQ, not when a connection merely opens; after a publish or a REQ it left unanswered, only an answer of that kind counts. A relay's CLOSED is answered with a new REQ after 30 s. A connection used only to publish closes after 60 s in which nothing was sent over it or answered; the relay's notices do not count. A REQ ended before its connection opens is never sent. | §10.3 asks for dead connections to be detected by a missing OK. The rest are ordinary defaults. The ninth review (§31): a relay that never ended a REQ was never judged and could stay the listening relay, and one that dropped each connection as it opened was tried every second. |
| Undelivered pairing steps | Resent every 30 s while the app is in the foreground and the invite lasts, as the same events. They are kept in the store with their pairing, so a restart loses none. A step still waiting for its relays' answers is not sent again meanwhile; the relay pool, too, sends an event once over a connection while it waits for its OK, and gives every publication of it that OK. | Relays keep one event per step and author, so resending is harmless. A step sent offline was lost when the app restarted before the network came back, and the pairing waited for the invite to expire (§29). The joiner's first step went twice, and the pool lost track of one copy: its connections failed for want of an OK that had come (§31). |
| Store format | Binary contents of one version. A store of any other version is not read, like a store that cannot be read: the app offers to delete it. While the feature is in development, each change of the format takes the next number, and the number goes back to 1 for the first release. A dot colour of the user's own that this build does not know reads as automatic, as a contact's does: a palette changed meanwhile must not cost the contacts (§27). A save rotates the keys when a secret of the previous save is missing, judged by digests of the secrets, so no call site can forget to. A pairing in progress is stored whole, Noise state included. | §8.5; a link pairing must survive app restarts at every step. Nobody has data to keep before the first release: reading the stores of development builds cost code, tests and review for nothing (§26). |
| Starting a share | The first position published is a fix that arrives after the share started, never the last fix the app had. | That fix could be hours old. |
| Hidden contacts | Their keys stay in the inbox subscription, and their states are read: a share is known, but not followed: no stream, no signals, no dot, no "Live updates off". Shown again, a share is followed at once. A share's time limit ends it on time, hidden or not: the app's clock wakes for the end of every share it follows. | Their states still arrive, e.g. the end of a share or the joiner's confirmations, and the inbox's size does not change when someone is hidden. A share was forgotten when hidden, so shown again a contact had no dot until its next state (§27). A hidden contact's share then outlived its time limit when the sharer's phone was off by then: only the view's clock enforced it, and it runs while the app is in the foreground and a contact who is not hidden is followed (§28). |
| After a restart | A contact's latest state is read once more, and only it: an older one is still refused, as is the latest one read again in the same run (spec §8; **review**). | Your finding in the sixth review (§28): what a state grants is kept in memory only (§8.5), but the rule that ignores a state not newer than the last one accepted took the re-read state for a replay, so a restarted viewer lost every running share until the contact's next state. Storing grants instead would put stream keys on flash, which §8.5 rules out. A restart still forgets that the latest grant's stream ended. The viewer learns it again from the stream's `end` while that is on the relays (15 minutes); after that, it matters only if the state sent with the `end` never arrived, and then a viewer that did not restart but was not watching at the time cannot tell either. |
| A contact's relays | Each state's relay list replaces the one from pairing. | A contact can change its relays; its states name the current ones. |
| Changing one's home relays | Spec §11: every contact gets a state naming the new list at once, in one shuffled batch, and a running share is re-keyed onto it. A contact counts as not moved until something new from it arrives through a current home relay. Until all have moved, and for at most 30 days, the inbox also reads the previous relays in the foreground; they stay allowed meanwhile. A change made with no contacts and no pairing under way tells no one. | Contacts learn one's relays only from one's states. Your change in the second review (§24): a week, then silence, was the worst kind of failure for a location share. |
| Repeating the new list | Each contact that has not moved gets the current state again on each UTC day the app runs, for as long as it has not moved, past the 30 days too. Not a contact that never finished connecting (offered for removal): it gets the new list once, is not waited for when deciding whether everyone has moved, and is not labelled. | A contact who opens CoMaps on day 40 still learns the new list from that day's state, and answers. The cost is one small state a day per such contact, sent only while the app runs. Your verdict in the third review (§25): kept, without contacts that never finished connecting. That they are not waited for either, so that the old relays are not read for 30 days for them, was mine, kept in the fourth (§26). |
| Answering a contact's move | A state naming relays other than those the user's last state to that contact reached gets the current state in answer, through the named relays the user allows, at once, or when the user allows one, or shows the contact again after hiding it; never to a hidden contact. It asks about the other relays only when none is allowed. An answer no relay accepts goes again as any state (next row). | Spec §11. Each relay is asked about once: asking as the answer went out took the place of the question that says what a relay is for, such as live updates once the contact shares (§24). |
| States no relay accepted | Each state counts as not delivered until a relay accepts it, also across a restart: the stored record of which relays the latest state to a contact reached is then empty. Such a contact gets the current state again whenever a relay connection opens, 30 s after a failure doubling to 5 min, when the app comes to the foreground, when a relay is allowed or the contact shown again, at midnight, when the app starts the core, and when the delivery job runs; not when the daily ratchet job reads the store, which connects nowhere. Within the same UTC day the same event goes again, after it a new state. All that are due leave in one shuffled batch, hidden contacts' too: hiding stops following a contact, not telling it about one's own share. Once no relay has accepted any state to a contact for a week, its states go again only while the app is on screen: not from the core in the background, nor from the delivery job. The week starts again when the contact names other relays, or the user allows one of them. | Spec §8. Your finding in the seventh review (§29): a state was published once, so a share started, stopped or re-keyed offline was lost until the next state. One rule for answers and re-sends: a contact whose relays do not hold the latest state gets the current one. The week: your decision in the ninth review (§31), for a contact whose relays take nothing for good. |
| A share's end, once more | Once a relay has accepted the state ending a share with a contact, the contact gets the current state once more on a later UTC day: at midnight if the app runs, else by the delivery job. Not while it is a recipient again. | Spec §8. Your decision in the seventh review (§29): a state can be read only until 01:00 UTC the next day, and an app open offline past then (a night flight) kept the share for good. |
| Deleting a contact one shares with | The contact's keys go at once. If a share with it ends then, ended at a process death, or ended without its end delivered twice, states without a share are made at that moment, one for that day and each of the next six, signed with their days' keys; only those and the contact's relays are kept, and sent as above until one is accepted and then another on a later day, for 7 days at most. | Your decision in the seventh review (§29). Keeping the channel instead would have left a phone taken from its owner with the keys of a contact the user believes deleted, for up to a week (T7). |
| A share interrupted by the process's death | Nothing goes to its recipients until the user resumes it or not: no re-send, no confirmation, no new relay list, each of which would end it. "Don't resume" sends each of them the end, and once more on a later day. An offer past its time limit holds nothing back. | Your decision in the seventh review (§29): until the user decides, contacts see the share as it was, stale, as for a phone that is switched off. "Don't resume" used to send nothing, so they saw the share until their app restarted on a later day. |
| Idle publishing | A fix is published when it moved at least max(20 m, both fixes' accuracies added) from the last one published, or is at least twice as accurate; at least 30 s apart, with the 5-minute heartbeat. | §10.3. Your compromise in the second review (§24); the clause for a sharper fix is mine. |
| The listening relay's echo | On the listening relay, the inbox subscription also asks for the share's own stream, of the inbox's epoch. A stream post accepted with `OK true` (not `duplicate:`) that has not come back 15 s later marks the relay deaf: the subscription moves to the next relay, and publishing to it goes on. Only the listening subscription judges, and only a post sent over its connection for the first time; a copy that comes back counts once it matches the REQ and verifies. It is tried again after 5 minutes alongside the relay in use, doubling to 30 (±20 %), until a post comes back over it. A reconnect does not clear the mark. A relay that has never sent a post back is not judged, except the default relays, which are judged from the start. Which relays have sent one back is kept in the store for as long as they are home relays (current or previous), so that one already deaf when the app starts is judged too; the first post of a share leaves before the listening subscription is open, so the check starts with the second. | §10.3. Your proposal in the second review, with one miss in 15 s as you chose, kept in the third (§25), where you also asked to keep the record across runs. The back-off and the trial alongside are mine: retrying a relay alone moved the inbox back onto a relay still deaf, for minutes. That the record lasts as long as the relay is a home relay, with no time limit, was mine, kept in the fourth (§26). The defaults: your question in the fourth, since a fresh install whose listening relay was deaf already was never judged; they were measured to send posts back (§24). They count in every run rather than being written into the record, so that one removed and added again is still judged: kept in the fifth review (§27). Since the ninth (§31), a pairing's steps, which go again after a lost OK, are no longer judged: a relay that took one twice and said nothing of the duplicate was marked deaf. |
| What a relay delivers | An event counts as received only once it matches the filters of the REQ it came for and its id and signature verify. A connection that sends more than 32 other events counts as failing (back-off), events for a REQ it never had included. Until a REQ sent again with other filters has its EOSE, events that match only its previous filters are dropped without counting, as are events for one of its last 16 REQs closed. | Spec §11: otherwise a relay that sends a broken copy first hides the intact ones, and junk costs key derivations. An honest relay may still answer the previous filters meanwhile (§24), and a REQ until it has the CLOSE. Junk under REQ ids never sent cost nothing before the ninth review (§31). |
| Names and relay URLs | A name has at most 64 bytes and no control characters; a relay URL at most 64 bytes of printable ASCII without spaces, quotes or backslashes (spec §5). The app checks names as they are typed. | So the largest message of each kind fits the size it is padded to: a state 506 of 512 bytes, `pair3` 465 and `pair2` 430 of 512, a position 253 of 256. Quotes and backslashes take two bytes in JSON and control characters six, so a state with four relay URLs full of quotes was too large, and the error ended the app (§26). |
| A store that cannot be read now | Only a missing file means "nothing stored". Another failure to open or read it deletes nothing, and nothing is written until a start has read the store or the user chose "Delete all live location data". A failed write is no store error: it is logged, and the next change writes everything again. The app tells the user the first time in a run that writing fails, without offering to delete anything. | A failed open (no free file descriptor) or a key store failing for a while must not cost the contacts. A failed write said the data could not be read, and offered to delete it (§25). Writes that keep failing lose every change since the last good one when the process ends, and keep keys the daily ratchet erased in the file; Android does not say so (§26). |
| Sending to a relay that needs consent | Asked about as "sending"; skipped until allowed. | Spec §11. |
| Answers to relay consent | Allow and Don't allow are kept until changed in Settings; Don't allow keeps the contact it was for, to list it. Not now is kept in memory only: the relay is asked about again the next time it is needed, at most once each time the app runs. | Your change in the third review (§25): a "Not now" that meant "never", and nowhere to see it, was a trap. |
| The dot colour | A name, or none, kept in the store; every state carries it (spec §8). Changing it sends the current recipients their state at once, in a shuffled batch, as the daily re-key would. A viewer keeps the colour of each contact's latest state, and ignores a name it does not know. | Your request in the third review (§25). The states of a running share already go to the current recipients each day, so the batch tells relays nothing new. |
| Low battery | Positions say `low` at 15 % and below, and sharing stops at the user's level, 0 (never) to 50 %, both only while the phone does not charge. A share started at or below the level runs until the battery has been above it (charging up to the level is not above it). A level chosen while sharing applies at once; the same level chosen again changes nothing. | `low` was in the payload (D12) but never set (§25). The exception, kept in the fourth review (§26): with levels up to 30 %, a share started at 25 % would otherwise stop at once, though the user just chose to share. |

The Android app (`android/app/.../livelocation`, `android/sdk/.../livelocation`) decided these:

| Topic | What the app does | Why |
|---|---|---|
| Where the switch is | Settings → Live location sharing, a section of its own: the switch, "What relays can see", then the settings, one row each with an icon and its value or what it does below the title, greyed and without values while the feature is off or its data cannot be read; deleting works either way. The relay lists open in dialogs. Below Android 7 the section is not listed, the left button does not offer the feature, "Turn on" does nothing, and an invite link says "This invite is for live location sharing, which needs Android 7 or later." While the feature is on, "Share My Location" in the main menu opens the feature's screen, which can still send the current location once. | Your changes in the second and third reviews (§24, §25); §11.1, §11.5. Below Android 7, the left button and invite links led to the explanation, whose "Turn on" started the core without the feature counting as on, again and again (§27). |
| The switch's title | "Live location sharing", with the note "When enabled, you'll find it in the main menu under Share My Location". | Your verdict in the third review (§25): no "(experimental)". |
| The settings from the feature's screen | Only through Settings → Live location sharing. | Kept in the third review (§25). |
| The sharing service | It goes foreground as soon as it starts, with the title alone when the share it was started for ended meanwhile, and only then checks whether there is anything to share, precise location and a notification that can be seen; else it stops. It stops with its latest start's id. | A service started to go foreground that stops before it does so crashes the app on Android 8 and later (§31). A start that came meanwhile, for a new share, keeps the service. |
| The sharing notification | Its channel has default importance without sound or vibration, so its icon shows in the status bar. On the lock screen it reads "Sharing your live location", without names. | Seen without being noisy; the names stay private on a locked phone. It is silent in effect already. Android's "Silent" importance (low) can leave the icon out of the status bar (`shouldHideSilentStatusBarIcons`, Android 10+), and the icon is what makes a share visible at a glance. A user may still choose "Silent" in the system settings; only blocking the channel stops the share. |
| "Re-checks before every publish" (§11.3) | Before passing on each fix, and on the system's block broadcasts (Android 9+). A heartbeat, which publishes without a new fix, is not checked on its own. | Fixes arrive every 2–30 s while sharing, so a blocked notification stops the share within one fix. A check per publish would need the core to ask the app each time. |
| Background location pace | Only while a share alone keeps location running in the background: 2 s at high accuracy when someone watches, else 30 s at balanced accuracy (§10.3). Navigation, track recording, Android Auto and the "waiting for position" mode keep their own pace; in the foreground the map's 500 ms applies. | Balanced accuracy is a hint: the fused providers honour it, a plain GPS provider does not. |
| Low battery | The service reports the battery level and whether the phone is plugged in. Plugged in, the share does not stop for the battery, and positions do not say `low` (above, core). | Stopping a share on a charging phone helps nobody. The service once reported 100 % while charging, which counted as the battery having been above the level (§25). |
| A fix without accuracy | Dropped, as are fixes with values out of range; out-of-range optional fields are left out. | The protocol requires an accuracy, and receivers drop a message with a bad field. Fused and GPS fixes carry one. |
| Turning the feature off | Stops any share, closes connections, and frees the core once the stop's messages have their relays' answers (at most 30 s). What no relay accepted then goes out later, by the delivery job (below), for a week at most. Deleting the data while it is off cancels the job and runs on the core's thread, after whatever it is doing: a core still sending (a stop's ends, the job's) goes without writing again, then the file and the Keystore keys go. Nothing else starts. | "No traffic when unused" includes the moment of deletion. Contacts must still learn that the share ended (§29), but not for ever: your fix in the eighth review (§30), the week a deleted contact is told for. A core still sending wrote the store again after Java had deleted it, readable under a new key if it erased a key meanwhile; your decision to delete at once anyway, though contacts may then not learn that a share just stopped has ended (§31). |
| The delivery job | A one-time WorkManager job with a network constraint, there only while the app is neither on screen nor sharing: on screen or sharing, the core runs and sends again by itself. It is scheduled for when the core says something is next due: a state no relay accepted (as soon as there is a network), a share's end once more on the next day, a deleted contact's. That time changes with what is due, not with each attempt to send it; each change takes the job's place, a run in progress too. The job runs the core if none runs, waits up to 30 s for the relays' answers, and frees it again; then it schedules the next run, or retries with WorkManager's back-off, from 30 s up to its cap of 5 hours. Also while the feature is off, for a week after it was turned off; never without a store, which it does not create; not for a contact whose relays have accepted nothing for a week (core, above). | Your decision in the seventh review (§29): a stop made in a tunnel would otherwise reach contacts only when the user opened the app again. WorkManager runs it after a reboot too, and in Doze's maintenance windows, when the core's own timers stand still. Your findings in the eighth review (§30): it repeated the core's attempts while the app was open, and with the feature off it never gave up. |
| The sharing indicator | A round button like track recording's, at the top right of the map, where track recording's is, or below it when both show, in every layout that has track recording's; the compass moves below both. While a route is planned, both sit 72 dp from the top, clear of the planning header (64 dp). Its icon is a pin with arcs on both sides, as large as the recording ring, with the number of people cut out of the pin ("99+" from 100). It blinks between grey and blue, in step with track recording's: each blinking starts on a common clock, one line added to upstream's `animateIconBlinking()`. A tap opens Manage sharing. It hides with the other map buttons. Its blinking stops with its view, e.g. when the buttons are made again for navigation. | Your changes in the third review (§25): the badge was cut off on some phones, the indicator covered the compass, and it should blink like track recording's, in blue; below track recording's, kept in the fourth (§26), where both indicators touched the planning header (40 dp from the top on short screens, 64 on others). |
| Adding a contact | The screen opens with a QR invite (10 min). "Share a link instead" cancels it and makes a link invite (24 h). "Paste invite" cancels the user's own open QR invite before joining. | One open invite per screen, so the two codes are never confused. |
| Share durations | 15 min, 1 h (preselected), 8 h, until stopped, or until a time of day picked on a clock (tomorrow if it has passed). A contact's details change the end of a running share, earlier or later, without re-keying. | §11.3's list, and your changes in the third review (§25). |
| Manage sharing | One screen starts and changes a share (§11.3). Ticking adds after 2.5 s without another tick, or when the screen goes; unticking removes at once, with whoever was ticked meanwhile. A change the core refuses says so. "Stop sharing with …" in a contact's details changes the share the same way. A share that waited for the notification settings starts on return, if its notification can be seen now. | Your design in the third review (§25); the 2.5 s kept in the fourth (§26). Each change of recipients re-keys the stream, with up to two minutes of silence for those already following; adding three people one after the other would do that three times. |
| Buttons | Filled for the screen's main action, outlined for the others, red for stopping and deleting: filled red "Stop sharing location" and "Stop all", outlined red "Stop sharing with …", "Delete contact" and "Cancel invite". | What CoMaps' own screens imply (§25): Start, Download and Log in filled; Register and Edit outlined; navigation's Stop filled red; the editor's Reset outlined red. |
| Leaving an open invite | "Leave the invite waiting?" → [Leave it waiting] / [Cancel invite], on back, the toolbar's arrow, and for the inviter only. | Your change in the third review (§25). A joiner's pairing goes on by itself, and its screen says so. |
| Screen titles | Each screen on top of another has its title, and the one below gets its title back however the screen goes. | "Cancel invite" closed the screen without going "back", which left "Add contact" as the title (§25). |
| Resuming after the process died | The map offers it in a dialog. "Resume" restarts the share with the same people and ends; without the permissions it needs, Manage sharing asks for them and then resumes. Manage sharing offers it too, at its top, until it is resumed or dismissed. Only the people whose end has not passed are offered; if every end passed after the offer, the app says so and forgets the share. "Don't resume" tells them that the share ended (core, above). | §8.5. Coming back from the notification settings resumed nothing, and a share whose ends had all passed was offered again and again (§25). |
| Relay consent questions | Queued; whichever live location screen or the map is in front asks them, one at a time, with [Allow] / [Not now] / [Don't allow] (core, above). A question dismissed with the activity counts as "Not now". The labels of a contact (§11.5) and Settings → Relays for contacts ask again. | Questions arrive at any time, often while the user is on the map. |
| A contact's dot | A circle, 20 dp across (16 until the third review), in the colour the sharer chose, or one derived from the contact's id (grey once old), with the name under it, in the layer of bookmarks' labels. A tap on either opens the sheet over the map (§11.4); "Center" zooms to the position at zoom 16. A long tap opens the usual place page of that point, titled with the name, from which one can route there. | Drape places no labels in the user mark layer. A tap on a name used to reach upstream code that aborts on an unknown mark type (§24). |
| The dot's sheet | A bottom sheet in the map's layout, as the place page is, not a dialog: the map stays bright and can be moved, the map buttons rise above it, and "Center" puts the contact in the part of the map above it, after it stops the map following the user's position (`Framework::StopLocationFollow`, as for a bookmark; also "Show on the map" in the contact's details). A drag down closes it, and so does whatever closes the place page: back, the main menu, the search bar on the map, planning a route, full screen; the search button leaves both open. A place tapped on the map takes its place; another contact's dot replaces its lines. It stays open while the contact's details are open, and comes back after a rotation. Hooks in `MwmActivity`: back, `closeFloatingPanels()` and full screen. It gets the navigation bar's room itself, before its first layout, and tells the map buttons where it rests after each layout pass. It asks for a layout pass at each step of its movement. | Your change in the fourth review (§26): the dialog dimmed the map, covered the map buttons, and closed when the map was touched. The behaviour gave the bar's room only after the sheet had started to open, and a layout listener sees the sheet before the behaviour moves it down: it opened over the bar, and the buttons hid (§27). Over the map, a SurfaceView, the window tells the compositor which of its parts are transparent only at a layout pass, and the behaviour slides the sheet up without one: its sides and the part behind the navigation bar showed the map (§28). Your finding in the eighth review (§30): while the map followed the user's position, it went back there at the next fix. |
| The left button | Settings → Interface → Left button setup offers "Share Live Location", from Android 7. It opens Manage sharing, where one picks whom to share with, as the indicator does; with no contacts yet, Share My Location, where one adds one; with the feature off, its explanation, where one turns it on. Its icon is that of the feature's settings. The main menu keeps "Share My Location", which opens the feature's first screen. | Your request in the fourth review (§26), its target kept in the fifth (§27). The label names the act of sharing, so the button goes where sharing starts. Share My Location stays in the menu because its screen (adding contacts, sending the current location once) has no other way in. |
| A contact that has not moved | Labelled "Hasn't picked up your new relays yet", and after the 30 days "Hasn't picked up your new relays". Its screen explains and suggests asking the contact to open CoMaps. A contact that never finished connecting is not labelled. | Your change in the second review (§24), kept in the third (§25); §11.5. |
| Opening an invite link | A link opened from outside the app asks "Connect with whoever created this invite? They will see your name, …" before anything is sent. A pasted invite opens directly. When the user refused or put off every relay the invite has, the screen names them, each with "Allow …", rather than calling the invite invalid. | Opening a link must not by itself send one's name or add a contact (§11.2). "Created", not "sent": in person nobody sent anything (§24). |
| TLS | Every relay connection gets a TLS context of its own. | A shared one resumes TLS sessions, and the session ticket links connections (spec §11). |
| Calls into the core | Calls without a result (fixes, foreground, battery, decisions, edits) are queued; at most 256 messages of one relay connection wait for the core's thread. | A core busy with a flooding relay must not freeze the UI. |
| Daily ratchet (D16) | A WorkManager job once a day while the feature is on. With the core not running, it reads the store (erasing the keys that are due), writes it and frees everything; nothing connects. While the core runs, it does nothing. Without contacts it only reads and writes the store. | D16. Scheduling it with the feature, rather than with the first contact, keeps it simple at no real cost. |
| Strings | English only, in `strings_live_location.xml`, outside the translation pipeline. | Experimental feature; translations once the texts settle. |
| Fixes across JNI | Unknown accuracy, speed and bearing are negative and altitude has a flag: no NaN crosses JNI, since the native side builds with `-ffast-math`. Strings cross as UTF-16 both ways. | JNI's "modified UTF-8" would turn a name with an emoji into text the core's strict JSON refuses. |

## 22. Phase 2 report

Phase 2 built the feature: the core in C++, the Android app around it, and tools to test it
without phones. [LIVE_LOCATION_DEVICE_TESTS.md](LIVE_LOCATION_DEVICE_TESTS.md) is the checklist for
the phones. A first brief run on two phones, and the review that followed, are in §23; the second
review, with your verdicts on the judgement calls, in §24; the third, after more runs on phones,
with the screens reworked, in §25; the fourth, which dropped compatibility with development builds
and made the dot's sheet behave as the place page, in §26; the fifth, before the full runs on
phones, in §27; the sixth, after a run on phones, in §28; the seventh, on updates sent while offline,
in §29; the eighth, on the delivery job and the map following the user's position, in §30; the ninth,
a review of the whole by a third party, in §31.

### What was built

| Part | Where | Size |
|---|---|---|
| Core: crypto (BIP-340 through libsecp256k1, NIP-44 v2, Noise NNpsk0, HKDF), Nostr events and the strict JSON profile, NLL v1 (invites, pairing, channels, streams, signals, receiving rules), relay pool, encrypted store, manager | `libs/live_location` | 9,950 lines |
| Tests of the core | `libs/live_location/live_location_tests` | 6,550 lines, 125 tests (71 at first, 79 after §23, 87 after §24, 95 after §25, 98 after §26, 100 after §27, 102 after §28, 110 after §29, 112 after §30) |
| Contacts' dots on the map, and a tap on them | `libs/map/live_location_marks.*`, `Framework`; a test in `map_tests` | |
| Desktop test peer (the core driven by line commands, plain `ws://`) | `libs/live_location/peer` | 630 lines |
| JNI host: the core's thread, OkHttp sockets, Keystore key wrapping | `android/sdk/src/main/cpp/.../livelocation` | 880 lines |
| SDK: facade, OkHttp transport, Keystore wrapper, models; location pace | `android/sdk/src/main/java/.../livelocation`, `LocationHelper` | 1,270 lines |
| App: foreground service, delivery and ratchet jobs, the switch and its settings, screens, the dot's sheet, the indicator's icon, the left button, hooks | `android/app/src/main/java/.../livelocation` | 4,340 lines |
| Python reference implementation, test peer, cross test, fixtures | `tools/python/live_location` | 4,800 lines |

### How it was tested

- **C++ tests**, with clang and GCC: the published NIP-44 and BIP-340 vectors; the NLL v1 vectors,
  reproduced byte for byte from the Python reference; the JSON profile's verdicts on the shared
  cases; and integration tests of whole phones against in-process fake relays that drop, refuse,
  duplicate, go silent or go down (two of three), or accept posts without delivering them. Mutating
  the code under test (a removed check, a wrong bound) makes the matching tests fail; that was
  checked for the protocol, the manager, the conversions, the second review's echo check, idle rule,
  relay moves and the answer's consent question (§24), and the third review's consent answers, echo
  record, contacts that never finished connecting, upgrade answers, dot colour and low battery, and
  the fixes from the code review that ended it: charging, failed writes, resuming and invites through
  relays not allowed (30 mutants, §25), and the fourth review's rules for relay URLs and names, the
  store's version, the notice of failed writes and the default relays' echo (12 mutants, §26), the
  fifth's hidden contacts and own dot colour (7 mutants, §27), the sixth's time limits of
  followed shares and reading the latest state again after a restart (7 mutants, §28), and the
  seventh's states sent again, the next day's repeat, deleted contacts, interrupted shares and
  pairing steps (21 mutants, §29), and the eighth's retries: their cap, the one when the app comes to
  the foreground, and a due time that does not move with them (4 mutants, §30), and the ninth's relay
  pool (an event published again on its way, a REQ without EOSE, the back-off and what ends it, the
  echo check's duplicates and broken copies, a REQ ended before its connection opens, notices, junk
  under unknown REQ ids) and retries (a week without an accepted state, pairing steps sent again; 31
  mutants, 30 caught, §31). The fake network also takes one phone offline.
- **Map**: a test taps a dot as drape reports it, on its name and on the dot itself, with and without
  the app's listener (`LiveLocationMarks_TapOnADot`). Without the fix it aborts, as the app did.
- **Cross-implementation, over a real relay** (strfry): the C++ core and the Python reference pair
  in both directions with matching codes, follow each other's shares, switch to live updates, and
  revoke, and each reads the other's dot colour. After a removal, the removed peer's old key opens
  none of the events published afterwards (12 of 12 refused). 15 checks, all passing. Between two
  C++ peers a live fix arrives in about 0.1 s.
- **Android**: the APK builds (fdroid debug, arm64). All 34 native methods are exported, and their
  JNI descriptors match the C++ parameter types. The Java parsers are tested on the JVM against
  views recorded from the C++ core (9 tests). Android lint, app and SDK: no errors. Its first run
  found seven in this code, of two kinds (posting the notification without an explicit
  notification-permission check, and Keystore calls without an API-level guard), now fixed; release
  builds abort on lint errors. One kind of warning remains in new code, on the two layouts of list
  rows: possible overdraw, their ripple background being painted where the theme paints one too, as
  in upstream's layouts.
- **Not as planned (§12):** no JVM tests of the OkHttp transport or the Keystore wrapper. Robolectric
  cannot fetch its Android runtime in this sandbox (upstream's own Robolectric test fails here the
  same way), and with mocks such tests would check little. Both run on every phone check.

### Definition of Done

| Item | Status |
|---|---|
| Two phones on different networks | To check on phones (device checklist, all checks) |
| Pairing in under a minute | Desktop: seconds over a relay. Phones: check 1 |
| A's marker follows within about 5 s | Desktop: about 0.1 s per fix once live. Phones: check 3 |
| Stop and revocation, with a test peer | Desktop and cross-implementation: passing. Phones: checks 4 and 5 |
| Time-limited shares end on time | Manager tests: passing. Phones: check 6 |
| Works with any 2 of 3 relays down | Manager and pool tests: passing. Phones: check 7 |
| No traffic when unused | Manager test: no connection without a reason. Phones: check 8 |
| Works without Play services | By construction (Android's own location providers, OkHttp). Phones: check 9 |
| Tests pass | Yes, as above |
| Battery and data measured for one hour | Only on phones: check 10 |
| A one-screen explanation of what relays see | In the app (Settings → Live location sharing → "What relays can see"); check 11 |

### What to review

One row of §21 is marked **review**, from the sixth review (§28): after a restart, a contact's latest
state is read once more, which amends the rule of spec §8 that ignores a state not newer than the
last one accepted. The eighth review's question (§30), retries without end with the feature on, is
answered in the ninth (§31): a week without an accepted state, then only while the app is on screen.

### Known gaps

- The changes of the sixth to ninth reviews (§28 to §31) have not all been checked on a phone yet:
  the dot's sheet drawn whole, a hidden contact's share ending at its time limit, a share followed
  again after a restart, updates sent offline arriving once the network is back, "Center" and "Show
  on the map" while the map follows the user, deleting the data right after turning the feature off,
  the sharing service's start, and a share waiting for the notification settings. The delivery job
  that sends updates while the app is closed has no test here, nor has when it is there and when it
  gives up.
- §11.5 once promised a test of whether each relay can be reached; none was built.
- English only.
- Phones whose makers kill background apps aggressively may stop the sharing service; only
  phones can show how often.
- The battery and data figures in §10.3 are still estimates until check 10.

### Building and testing

```bash
# C++ core and tests (desktop)
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DSKIP_TOOLS=OFF && cmake --build build --target live_location_tests live_location_peer
build/live_location_tests
# Cross-implementation test (tools/python/live_location, see its README)
.venv/bin/python -I cross_test.py ../../../build/live_location_peer path/to/strfry
# Android
cd android && ./gradlew assembleFdroidDebug -Parm64 -PdisableHWAsan
./gradlew :sdk:testDebugUnitTest --tests 'app.organicmaps.sdk.livelocation.*'
```

## 23. Review of Phase 2 (2026-10-13)

A brief first run on two phones: pairing and the rest worked, but no contact's dot ever appeared on
the map. A review of the code found two serious bugs and five more problems, and three nits. Each
was checked here before it was fixed. Each fix has a test that fails without it, except where noted.

| Finding | Verdict | Change | Where |
|---|---|---|---|
| No dot on the map | **Right, two causes in drape.** Two C++ peers over the real default relays exchanged positions in 0.4 s, so the core was fine. The desktop app, rendered under Xvfb, showed the dots missing. Upstream drape passed a mark's `m_needOverlay` as the `subID` of its coloured symbol, so a mark that asked for no overlay got one anyway. The user mark layer is not part of the overlay tree, so that overlay never became visible and the circle was never drawn. Titles in that layer are never placed either | `needOverlay` goes in its own argument, and every other mark keeps the `subID` it had. Names go to the layer of bookmarks' labels. Rendered on the desktop before and after; drape's tests pass | `libs/drape_frontend/user_mark_shapes.cpp`, `libs/map/live_location_marks.*` |
| 1. Changing home relays reaches no contact | **Right.** Nothing told contacts; during a share the listening relay and the viewers' signals parted | Every contact gets a state naming the new list, and a running share is re-keyed onto it. For a week, the current state is sent again daily and the old relays are still read | spec §11; §21 |
| 2. One dishonest relay hides what honest ones deliver | **Right**, reproduced: a forged copy sent first left pairing at "Waiting". The Python test peer had the same bug | An event counts as received only once it matches its REQ and verifies | spec §11; `relay_pool.cpp`, `peer.py` |
| 3. An invite link pairs without a tap | **Right**: step 2 sent the name, step 3 added the contact | Opening a link from outside the app asks first; nothing is sent before "Connect" | §11.2 |
| 4. D16 was not implemented | **Right**, and not listed as a gap | A daily WorkManager job erases due keys while the app is not used; T7 says so | T7; §21 |
| 5. A failed read destroys readable data | **Right, both paths** | Only ENOENT is "nothing stored"; nothing is written before a start has read the store or the user deleted it | §21; `store.cpp`, `manager.cpp` |
| 6. TLS session resumption links connections | **Right**: one OkHttp client, one session cache | A TLS context per connection (no test: it needs Android's TLS stack) | §21 |
| 7. A flooding relay can freeze the app | **Right**: three key derivations per contact for every inbox event, an unbounded queue, and the UI waiting on every call | Events nobody asked for, or that fail verification, are dropped before any work, and a relay that sends more than 32 fails. At most 256 messages per connection wait, and calls without a result are queued instead of waited for (the last two untested: they are in the Android layer) | `relay_pool.cpp`; §21 |
| Nits | **Right**: UBSan reports the null `memcpy`; the non-unity build fails on three missing includes; GCC `-O3` warns five times | Fixed; the non-unity build passes, and GCC no longer warns | `secp256k1_sha256.c`, tests, `bytes.hpp` |

**Tests now.** 79 C++ tests, passing with clang 18 (unity and non-unity builds) and GCC 13. The cross-implementation
test passes 13 of 13 over strfry. Two C++ peers pair and share over the real default relays (nos.lol,
nostr.mom, relay.nostr.net): the viewer had the sharer's first fix 0.4 s after it was given. The APK
builds.

**Still open.** A contact who opens CoMaps on none of the days of the week after a relay change
keeps sending to the old relays until a later state reaches it (spec §11 says so). *Since
addressed (§24): contacts answer, and the old relays are read until everyone has moved.* The device
checklist's runs, battery and data figures above all, are still to come.

## 24. Second review of Phase 2 (2026-10-15)

Your verdicts on the fourteen judgement calls of §21, a proposal to catch a relay that stops
delivering, and a crash from a light test on a phone. Each claim was checked here before it was acted
on. Each change has a test that fails without it, except where noted.

**The judgement calls.**

| # | Call | Verdict | Change | Where |
|---|---|---|---|---|
| 1 | Pairing has connections of its own | Keep | — | §21 |
| 2 | A background sharer listens on one relay, even while live | Keep. Checked: while live, a dead listening relay shows as a missing `OK` within 10 s, and a viewer's signal holds live mode for 120 s and comes every 60 s, so live mode survives the move | Your echo check, below | §10.3 |
| 3 | Daily confirmations only while the app is open or sharing | Keep | — | §21 |
| 4 | Hidden contacts stay in the inbox subscription | Keep. Checked: as you said, padding to multiples of 8 already hides one key more or less, unless the count crosses a multiple of 8 | — | §21 |
| 5 | Changing relays during a share | Settled in §23: the share is re-keyed onto the new relays | — | — |
| 6 | Where the switch is | Change | A section of its own, Settings → Live location sharing: the switch, then the settings, greyed and without values while the feature is off; deleting works either way. While it is on, "Share My Location" opens the feature's screen, which also sends the current location once. "Share live location" replaces the second "Share my location" | §11.1, §21 |
| 7 | The notification | Keep. Your question, whether it could be silent: it is in effect, with no sound or vibration. Android's "Silent" importance can leave its icon out of the status bar, and the icon is what shows a share at a glance | — | §21 |
| 8 | Background location pace | Keep the pace. An idle fix is published only after a real move | Publish when moved ≥ max(20 m, both fixes' accuracies added): your compromise between my max(50 m, the sum) and your more than 10 m and the larger accuracy. Or when the fix is at least twice as accurate (mine). Your first rule set a lower bar than the 50 m rule for every fix better than 50 m, and with equal accuracies 57 % of a still phone's fixes pass the larger accuracy, against 10 % for the sum | §10.3, §21 |
| 9 | The "Sharing with N" chip | Change. Checked: the chip already opened Manage sharing, two taps to stop; the four were through the menu. It was hidden in planning and navigation | A round indicator like track recording's, with the number of people; a tap opens Manage sharing | §11.3, §21 |
| 10 | QR first, a link second | Keep | — | §21 |
| 11 | The old relays read for a week | Change | Contacts answer a relay change through the new relays; the old ones are read until everyone has moved, for at most 30 days; contacts that have not moved are labelled | spec §11; §11.5, §21 |
| 12 | The D16 job whenever the feature is on | Keep | — | §21 |
| 13 | Flood limits: 32 bad events, 256 waiting messages | Keep. Checked: an honest burst is one to three stored events per contact, so 256 is enough for at least 85 contacts, where §7 plans for 50. But an honest relay could count towards the 32: a REQ sent again may still be answered for its previous filters until its EOSE | Those events are dropped without counting | §21 |
| 14 | The join question for a scanned QR code | Keep, reworded | "Connect with whoever created this invite?" | §11.2 |

**The echo check (your proposal).** The listening connection also subscribes to the share's own
posts. Measured first, on eight public relays, the three defaults among them: every accepted event
came back to the connection that published it, at most 114 ms after its `OK`, and an exact duplicate
(`OK true` with `duplicate:`) never did. Built as you chose: one miss within 15 s, and a relay that
has never sent a post back is not judged. The back-off (5 minutes, doubling to 30) and trying the
relay again alongside the one in use are mine: retried alone, a relay still deaf took the inbox
back for minutes. The tests found a second bug on the way: a second relay's copy of a post was lost
to deduplication, and that relay judged deaf. §10.3 and §21 have the details; spec §11 makes the
check optional.

**The crash.** A tap on a contact's dot or name aborted the app. The names are in the layer of
search marks (§23), so drape reports a tap on one as a tap on the mark, and
`Framework::FillUserMarkInfo()` had no case for this mark type: its default is `CHECK(false)`. It
was my regression from §23's fix, and the sheet that §11.4 specifies had never been built either.
A tap now opens that sheet over the map (your choice over the contact screen), and a tap on the dot
itself, which has no overlay, finds it by position. Map test: `LiveLocationMarks_TapOnADot`.

**Found on the way.**

| Finding | Change |
|---|---|
| Stores of version 2 were refused once stores became version 3: the decoder accepted only version 1 and the current one | A range check. A test reads stores of every earlier version |
| Labels that change with time alone (the 30 days, the waiting week) were refreshed only when something else changed | Refreshed on each tick of the clock |
| Answering a relay change asked about every relay of the contact's that the user had not allowed. Each relay is asked about once, so when the contact then shared, the question that says live updates need the relay never came. Found while recording the view fixtures | The answer asks only when no relay it may use is named |
| No answer was sent when the user allowed a relay later, or showed a hidden contact again | It is |
| The repeats of the new list stopped after the week, so a contact who opened CoMaps later never learned it | They go on until the contact has moved (a **review** row in §21) |
| Commit 205a3945, "a tap on a contact's dot no longer aborts", also holds most of the echo check's code; 579c1cd2 has the rest | Left as pushed, rather than rewrite the branch's history. Say if you want them split |

**Tests now.** 87 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13,
and the map test with GCC. The map library's whole suite has seven failures that are not this
branch's: with upstream's `libs/map` built in the same tree, the same seven fail. Six of them pass
when run alone (they depend on files and settings that earlier tests leave behind), and `MapApiGe0`
expects `cm.at` links that upstream's ge0 parser does not list. The cross-implementation test
passes 13 of 13 over strfry, the JVM tests 8 of 8, and lint finds no errors. The APK builds.

**For your verdict:** the six rows of §21 marked **review**.

## 25. Third review of Phase 2 (2026-10-21)

More runs on phones, with screenshots of every screen: your verdicts on the six rows of §21 marked
for review, 21 changes to the screens, a new setting, and five findings in the code with three
nits. Each claim was checked here before it was acted on. Each change in the core has a test that
fails without it (30 mutants, all caught: 22 for the round's changes, 8 for the code review at the
end); the app's changes have none, there being no phone or emulator here, and are for the runs on
phones.

**The judgement calls.**

| # | Call | Verdict | Change | Where |
|---|---|---|---|---|
| 1 | Repeating a new relay list until a contact moves | Keep, but not to contacts that never finished connecting | They get the new list once. Nobody waits for them either: the old relays are not read for them, and they are not labelled as not moved, being offered for removal instead (**review**: that much is mine) | spec §11; §21 |
| 2 | The echo check's back-off | Keep | — (finding 2 below) | §21 |
| 3 | The switch's title | Change | "Live location sharing", without "(experimental)" | §11.1 |
| 4 | The settings only in Settings | Keep | — | §21 |
| 5 | The indicator | Change: blink like track recording's, in blue | It blinks between grey and blue, in step with track recording's; items 1 to 3 below | §11.3, §21 |
| 6 | The labels of contacts that have not moved | Keep | — | §21 |

**The screens.**

| # | Your item | Change |
|---|---|---|
| 1 | The indicator covers the compass | The compass moves below the indicators. It moved for track recording's alone |
| 2 | Its badge is cut off; the number could be part of the indicator | The number is cut out of the pin (your pick, A, of the mockups); "99+" from 100 |
| 3 | Above or below track recording's | Below it, and in its place while track recording is off (**review**) |
| 4 | Dots slightly bigger | 20 dp across, from 16 |
| 5 | The icon slightly too small, on the map and in Settings | 1.23 times larger in both: on the map as large as the recording ring |
| 6 | The Settings entry's summary, a list like the others | "Name, dot color, relays, live updates" |
| 7 | The settings page like the other settings pages | No section titles or dividers; a row each with an icon and its value or what it does below: Appear as, Dot color, Relays (the list, moving up, removing and adding in a dialog), Relays for contacts, the two live update switches, Stop sharing at low battery (Never, 5, 10, 15, 20, 30 %), Delete |
| 8 | Is there a rule for filled and outlined buttons? | Not a written one. CoMaps' screens imply one: the screen's main action filled (Start, Download, Log in), the others outlined (Register, Edit), stopping red (navigation's Stop filled, the editor's Reset outlined). Applied as you chose |
| 9 | "Stop sharing location" while sharing | In red, where "Share live location" was |
| 10 | Hide's explanation as its subtext | Done |
| 11 | After "Cancel invite" the title stays "Add contact" | A screen's title now comes back however the screen above it goes. "Cancel invite" closed the screen without going back, which kept the title |
| 12 | The "Sharing with" row below "Add contact" | Done |
| 13 | "Contacts" → "Contact details" | Done |
| 14 | No "Hide" on the map's sheet | Gone from the sheet; it is in Contact details |
| 15 | Wording | "Sharing their location with you", "Sharing your location with them (until …)" |
| 16 | No section title on Share My Location; "What relays can see" in Settings, usable while off | Done |
| 17 | Changing a share's end in Contact details | "Change", earlier or later: the same stream, no re-key |
| 18 | Any length in "For" | "Until…", a time on a clock, tomorrow if it has passed |
| 19 | "Stop sharing with …" in Contact details | Done, outlined red |
| 20 | One Manage sharing for starting and changing a share | Done: ticked at the top, unticked below with "For" first, "Stop all" at the bottom. Ticks are added together after 2.5 s without another, or when the screen goes (**review**), since each change re-keys the stream; unticking is immediate |
| 21 | Leaving "Add contact" with an invite open | "Leave the invite waiting?" → [Leave it waiting] / [Cancel invite] |

**Your new setting: the dot colour.** Settings → Dot color: a grid of CoMaps' bookmark colours
without the greys, which mean an old position, or "Automatic", the default, which leaves the colour
to each contact's app as before. The colour travels in every state (spec §8, `color`), and a change
reaches the current recipients at once. A viewer ignores a name it does not know, and a `color` that
is not a short string, without discarding the state and its grant. The Python reference sends and
reads it, and the cross test checks it both ways.

**The findings.**

| Finding | Verdict | Change | Test |
|---|---|---|---|
| 1. "Not now" is permanent and invisible | **Right**: the answer was stored as a refusal, never asked again and never shown | Three answers: Allow; Not now, asked again the next time the relay is needed, at most once per run; Don't allow, kept with the contact it was for. A contact none of whose relays may be used is labelled "Messages to Bob need relay.example.org", and so is a contact whose live updates are off; a tap on the label asks again, in its details and in Manage sharing. Settings → Relays for contacts lists the refused relays with "Allow" | `Manager_NotNowAsksAgainInTheNextRunDontAllowNever` |
| 2. The echo record is in memory only | **Right**: a relay that stopped delivering before the app started was never judged | Kept in the store, for as long as the relay is one of the user's home relays (**review**: rather than for a fixed time; a relay deaf for good would otherwise be trusted again) | `Manager_ARelayThatEverSentAnEventBackIsJudgedInEveryRun` |
| 3. After an upgrade from a version 1 or 2 store, some contacts never answer | **Right**: the upgrade took each contact's relays as already reached by the last state, so a contact that had learned new relays before was never answered | The upgrade records nothing as reached: each contact's next state is answered once | `Manager_ReadsStoresOfEarlierVersions`: Bob's grant, his position, and Alice's answer |
| 4. Settings → Live location sharing appears on Android 5 and 6 | **Right**: only the switch inside was hidden | The entry is not listed below Android 7 | — |
| 5. With a store error, the settings show defaults; edits fail silently; adding a relay says "invalid" | **Right** | The settings say whether the store was read; if not, the rows show their titles only, greyed, with deleting still possible, as while the feature is off | The flag's parser, on the JVM |
| Nit: each post sent back for the echo check costs key derivations for every contact (≈45 µs each) | **Right** | Posts of the share's own stream are dropped before any | — (cost only) |
| Nit: the badge could be attached after the indicator went | **Right** | Gone with the badge | — |
| Nit: the dot's sheet is rebuilt with every position | **Right** | It is built once and updates its lines | — |

**A correction.** I said earlier that positions say `low` at 15 % battery. Nothing ever set the
flag. Now positions say `low` at 15 % and below while the phone is not charging, and the sheet and
the contact's details show "Battery low".

**Found on the way.**

| Finding | Change |
|---|---|
| A share started at or below the stop level stopped at once, at the battery report that comes with the sharing service's start. With levels up to 30 %, starting to share at 25 % would have stopped at once | Such a share runs until the battery has been above the level; a level chosen while sharing applies at once (**review**) |
| The phones' stores hold every earlier "Not now" as a refusal, the old app's only one: read by this version, they would have become "Don't allow" | Refusals in a store older than version 4 are dropped: those relays are asked about again |
| The settings view of a core that is not running (an empty object) read as the user's settings | Without the flag, the settings count as unreadable |
| The echo check never judges a share's first post: it leaves before the listening subscription is open. The second post does | Noted in §21; the test shares two posts |
| §11.5 promised a test of whether each relay can be reached; none was built | Taken out of §11.5; listed under known gaps (§22) |

**A review of this round's code.** Before the APK went out, a reviewer went over this round's
changes. Its seven findings, each checked here first:

| Finding | Verdict | Change | Test |
|---|---|---|---|
| 1. The indicator's blinking runs on after the map's buttons are made again (navigation, route planning), unseen, at every frame | **Right**: nothing stopped it when its view went | It stops with its view | — |
| 2. Plugging in counts as the battery having been above the stop level: the service reported 100 % while charging, so a share started at 4 % stopped when the phone was unplugged at 4 % | **Right** | The service reports the level and whether the phone is plugged in. Plugged in, positions do not say `low` and the share does not stop; only a level above the stop counts as above | `Manager_LowBattery` |
| 3. Picking the same stop level again stops a share started below it | **Right**: any pick counted as a level chosen while sharing | The same level picked again changes nothing | `Manager_LowBattery` |
| 4. Resuming can dead-end: after the notification settings, nothing resumes and Manage sharing does not show the share; when every end has passed, the map offers to resume again and again, and "Resume" leads to Manage sharing without a word | **Right**, both | Manage sharing shows the share to resume at its top, with [Resume] / [Don't resume], until it is resumed or dismissed. The core offers only the people whose end has not passed; when every end passed after the offer, the app says so and forgets the share | `Manager_OnlyWhatHasNotEndedResumes` |
| 5. After a write fails, Settings greys out, and the screens say the data cannot be read and offer to delete it | **Right**: the core reported a failed write as a store error | A failed write is logged; the next change writes everything again. Only a store that cannot be read is an error | `Manager_AFailedWriteIsNoStoreError` |
| 6. An invite whose relays the user all refused or put off says "This isn't a valid invite, or it has expired", and so does the same link again | **Right** | The screen names those relays, each with "Allow …", which allows it and joins | `Manager_AnInviteThroughRelaysNotAllowedNamesThem` |
| 7. In Manage sharing, unticking someone can keep them: ticks restored with the screen's state on Android 7 to 8.1 come back into the change, and a change the core refuses (someone else's end has just passed) fails without a word. After a rotation, the "Until…" clock's OK does nothing | **Right**, all three | Ticks are not kept with the state, as the screen adds them when it stops. Unticking leaves out anyone already sharing or whose end has passed, and a refused change says "The share could not be changed." The clock goes with a rotation, as the "For" list already did | — |

Found on the way: a failed change of a running share, adding someone or changing an end, said
"Sharing could not start."; it now says "The share could not be changed.". And two things in
upstream's map buttons, left as they are: track recording's observer is never removed, so map
buttons made again for another mode stay in memory, and react, until the map screen goes; and
track recording's blinking never stops, also after recording has.

**Tests now.** 95 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13,
and the map's tap test with the larger dots. The cross-implementation test passes 15 of 15 over
strfry, the JVM tests 9 of 9, and lint finds no errors. The APK builds.

**For your verdict:** the five rows of §21 marked **review**.

## 26. Fourth review of Phase 2 (2026-10-22)

More runs on phones: your verdicts on this round's five calls and on the five before them, dropping
compatibility with development builds, two findings in the code with two nits, ten observations on
the screens, and a new action for the map's left button. Each claim was checked here before it was
acted on. Each change in the core has a test that fails without it (12 mutants, all caught); the
app's changes have none, there being no phone or emulator here, and are for the runs on phones.

**Compatibility with development builds, dropped.** Your call: nobody has data worth keeping before
the first release, so nothing is kept for earlier builds. Gone: reading the store's versions 1 to 4,
each with its additions; what reading an older one did (every contact's next state answered once
after versions 1 and 2; refusals forgotten before version 4); and the test that rewrote stores byte
by byte (`Manager_ReadsStoresOfEarlierVersions`). The store has one layout, version 5. Each change of
the format during development takes the next number, and the number goes back to 1 for the first
release (§21). A dot colour the store does not know no longer read as none, but made the store
unreadable (undone in the fifth review, §27). Kept, as you asked: a store of another version cannot
be read, so the app offers "Delete all" (`Manager_AStoreOfAnotherVersionCannotBeRead`); and unknown
members of a message are ignored (spec §5, §12). Nothing else in the code
existed for earlier builds. This build cannot read the stores of the previous one: the phones need
"Delete all live location data", then connecting again (device checklist).

**The calls of this round.**

| # | Call | Verdict | Change |
|---|---|---|---|
| 1 | A failed write is no store error | Change: tell the user once per run, without offering to delete | The core says when writing starts to fail, and again only after a write has worked meanwhile (`OnWriteFailed`). The app says so once each time it runs, on the map or the feature's screen, whichever is in front, with only OK: "CoMaps couldn't save your live location data. Until it can, recent changes, such as a new contact or new relays, are lost if CoMaps closes, and keys that should have been erased stay on this phone. CoMaps keeps trying; freeing up storage space may help." It waits its turn with the relay questions and the notice that sharing stopped because its notification was off, in one queue |
| 2 | Resuming only after "Resume" | Keep | — |
| 3 | The clock and the "For" list close on rotation | Keep | — |
| 4 | One "Allow …" per relay | Keep | — |
| 5 | Upstream's two bugs in the map buttons | Leave them out of this PR | Left as they are, for the fixes you will send upstream |

**The calls before.** All five kept: contacts that never finished connecting are not waited for;
the echo record has no time limit; a share started at or below the stop level runs; the indicator
sits below track recording's; ticked contacts are added after 2.5 s. Their marks in §21 are gone.

**The findings.**

| Finding | Verdict | Change | Test |
|---|---|---|---|
| A relay URL with quotes or backslashes ends the app | **Right**, and names too. Quotes and backslashes take two bytes in JSON, so four relay URLs of 64 bytes full of them make a state larger than 512 bytes; the error that throws on the core's thread is caught by nothing, and the app ends. Control characters take six bytes, so a name of them does the same to `pair2` and `pair3`. Spaces were refused already | Relay URLs are printable ASCII without spaces, quotes or backslashes; names have no control characters (spec §5). The app refuses such a name as it is typed: "A name can't contain tabs or line breaks." The largest message of each kind fits: a state 506 of 512 bytes, `pair3` 465 and `pair2` 430 of 512, a position 253 of 256. The Python reference has the same rules | `Messages_TheLargestFitTheirSize`, `Manager_RelaysAndNamesFitTheMessagesTheyGoIn`, `Invites_RelaysAndEncoding` |
| Should the echo record start with the default relays? | **Yes**: a fresh install, or one after "Delete all", whose listening relay was deaf already was never judged. The defaults were measured to send every post back (§24) | The default relays count as having sent posts back in every run, rather than being written into the record (**review**): a default removed and added again is still judged, and the record keeps only what was seen | `Manager_TheDefaultRelaysAreJudgedFromTheStart`; the test of the record now uses a relay of the user's own |
| Nit: Contact details is rebuilt with every position | **Right** | Positions update its lines in place, as on the map's sheet | — |
| Nit: "Stop sharing with …" in Contact details keeps people whose end has just passed, and fails silently | **Right**, both | One helper for Contact details and Manage sharing: it leaves out anyone whose end has passed, and a change the core refuses says "The share could not be changed." | — |

**The screens.**

| # | Your item | Change |
|---|---|---|
| 1 | Contact details: "Hide on the map" above "Show on the map", and how long one shares above the last update | Done |
| 2 | The indicator's and Settings' icons cut off at the sides | The arcs drawn nearer the pin, at 88 %, so that the icons, 1.23 times larger since the third review, stay inside their 24 dp. Rendered here before and after |
| 3 | Another icon for "Allow viewers to request live updates" | Upstream's "update" icon, two arrows turning in a circle, as in the downloader's "Update Map" |
| 4 | How much more battery live updates use | Only estimates so far (§10.3), until check 10 measures it: while someone watches, about 4–8 %/h on LTE; unwatched, 0.5–1 %/h standing still and 1–3 %/h walking. That is several times as much, so "slightly more" would understate it. "This uses more battery." stays until the measurement; a viewer who looks for a few minutes costs the sharer little |
| 5 | "Dot color" → "Color you appear as" | Done |
| 6 | "What relays can see" | Done as you wrote it, but for one word: "Your live location is always sent encrypted", not "Your location", since "Send current location" on Share My Location sends a plain link, as the menu's "Share My Location" does without the feature. "IP address" also in the relay questions and in Settings, so that the app uses one term (§11.4, §11.6) |
| 7 | "Start sharing with" → "Start sharing" | Done |
| 8 | The indicators too close to the route planning header | Both sit 72 dp from the top while a route is planned: the header's 64 dp and the 8 dp the indicators keep from the screen's edges. On screens less than 400 dp high they were 40 dp from the top, under the header. This moves track recording's indicator too, since ours stacks below it: upstream's `track_recorder_status_top_margin` goes from 64 to 72 dp, and the layout for short screens uses it too. Navigation is unchanged |
| 9 | The sheet covers the zoom and my-position buttons | They rise above it, as above the place page (item 10) |
| 10 | The sheet like the place page | A bottom sheet in the map's layout, as the place page is, instead of a dialog: the map stays bright and can be moved and zoomed, a drag down closes it, and so does whatever closes the place page (back, the main menu, the search bar on the map, planning a route, full screen). A place tapped on the map takes its place; "Center" puts the contact in the part of the map above it; it stays open behind Contact details and through a rotation (§11.4, §21) |

**Your new action: "Share Live Location" on the left button.** Settings → Interface → Left button
setup lists it after upstream's four. It opens Manage sharing, where sharing starts, as the
indicator does (**review**: the label names the act, so the button goes where it starts); with no
contacts yet, Share My Location, to add one; with the feature off, its explanation, to turn it on.
Its icon is the feature's, as in Settings. Upstream hides a menu item that the left button
duplicates; the main menu keeps "Share My Location", since its screen, with adding contacts and
sending the current location once, has no other way in.

**Tests now.** 98 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13,
and the map's tap test. The cross-implementation test passes 15 of 15 over strfry, the Python
reference's tests 305 of 305, the JVM tests 9 of 9, and lint finds no errors. The APK builds.

**For your verdict:** the two rows of §21 marked **review**.

## 27. Fifth review of Phase 2 (2026-10-22)

A light run before the full runs on phones: eight items, and your verdicts on the two calls of the
fourth review. Each claim was checked here before it was acted on; one did not hold (item 7). Each
change in the core has a test that fails without it (7 mutants, all caught); the app's changes have
none, there being no phone or emulator here, and are for the runs on phones.

**The calls of the fourth review.** Both kept: the default relays count as having sent posts back in
every run, rather than being written into the record (a default that stops delivering is left like
any other relay, and the record holds only what was seen); and "Share Live Location" opens Manage
sharing, with its two fallbacks. No row of §21 awaits a verdict now.

**The items.**

| # | Your item | Verdict | Change | Test |
|---|---|---|---|---|
| 1 | Share My Location without contacts: no greyed share button, and another text | Done | No "Share live location" without contacts; "No contacts yet. Add a contact to share your live location." | — |
| 2 | The dot's sheet opens over the navigation bar, then corrects itself | **Right**, and mine. The bottom-sheet behaviour gives a sheet the bar's room only after the sheet's first layout, by which time it had started to open towards where it would rest without that room; the next layout, at a position update, put it right | The sheet gets the bar's room itself, read from the window before its first layout, and the side bars' beside it; the behaviour's own is off. Should its height still change while it moves, it is laid out again once it rests | — |
| 3 | The zoom and my-position buttons disappear while the sheet is open | **Right**, and mine. A layout listener told the buttons where the sheet was, but it runs before the behaviour moves the sheet down from the top of the map; told the sheet filled the map, the buttons hid, at every position update. Upstream's place page works around the same thing by reporting where it was before | The sheet tells the buttons where it rests after each layout pass, and where it is as it moves | — |
| 4 | A contact shown again after "Hide on the map" stays off the map until its next state | **Right**, in the core: hiding forgot the contact's share, and a hidden contact's states were not read for one, so nothing was left to follow | A hidden contact's states are read as any other's: its share is known, but not followed (no stream, no signals, no dot, no "Live updates off"). Shown again, it is followed at once, its relays asked about where needed and live updates asked for, unless its time limit passed meanwhile. Its status says it shares, above "Hidden" | `Manager_AContactShownAgainIsFollowedAtOnce`, `Manager_LiveUpdatesNeedTheListeningRelay` |
| 5 | Android 5 and 6: the left button and invite links lead to the explanation, whose "Turn on" starts the core, in a loop | **Right**: "Turn on" saved the switch and started the core, and below Android 7 the feature still counted as off | As you suggested. The left button setup does not offer "Share Live Location" below Android 7; an invite link there is taken, and the map says "This invite is for live location sharing, which needs Android 7 or later."; "Turn on" does nothing there | — |
| 6 | The docs say search closes the sheet | **Right**: the search button leaves it open, as it leaves the place page. The search bar on the map after a search closes both, and a search result's place page takes the sheet's place | §11.4, §21, §26 and the checklist corrected | — |
| 7 | On tablets, the end of route planning closes the place page but not the sheet | **Does not hold.** `closeAllFloatingPanelsTablet()` returns at once unless the tablet layout is on, and `tabletLayout` is false in every resource folder that sets it (values, values-land, values-w1020dp). Tablets get the phone layout, where route planning ends through `closeFloatingPanels()`, which closes the sheet | None: a hook in code that never runs would only add to the changes to upstream code | — |
| 8 | An own dot colour this build does not know should read as automatic again | Agreed, for your reasons: the store's authenticated encryption already catches damage; a palette change keeps the layout, and so the version; and nothing else treats colours so strictly | It reads as automatic again, and the contacts stay | `Manager_AnOwnColourThisBuildDoesNotKnowIsAutomatic` |

**Tests now.** 100 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC
13, and the map's tap test. The cross-implementation test passes 15 of 15 over strfry, the Python
reference's tests 305 of 305, the JVM tests 9 of 9, and lint finds no errors. The APK builds.

## 28. Sixth review of Phase 2 (2026-10-23)

A run on phones found the changes of the fifth review working, and three problems; you confirmed
that item 7 of §27 (tablets) did not hold. Each finding was checked here before it was acted on.
Each change in the core has a test that fails without it (7 mutants, all caught, and 2 in the Python
reference); the sheet's change has none, there being no phone or emulator here, and is for the next
run on phones.

| # | Your finding | Verdict | Change | Test |
|---|---|---|---|---|
| 1 | A hidden contact's share can show as running after its time limit, when the sharer's phone was off at the time | **Right**, as you traced it: a followed share's time limit was enforced only by the view's clock, which runs while the app is in the foreground and a contact who is not hidden is followed, and when a contact is shown again. Spec §12 has a recipient enforce `until` locally, whatever the sharer does | The clock that already wakes the app for the ends of its own share, the invites' expiry and midnight also wakes it at the end of every share it follows, hidden contacts' included; it ends them and tells the app | `Manager_AContactShownAgainIsFollowedAtOnce`, which now also checks while Alice is hidden; `Manager_TimeLimitsAndStop`, the dot going at the time limit itself |
| 2 | Closed and opened again while a contact shares, the app shows no dot for them until their next state | **Right**, and a contradiction between the spec and the design. The design keeps what a state grants in memory only and has a restarted viewer re-read its grants from the relays (§8.5); but the store keeps the last state's `seq`, and the spec ignores a state that is not newer. The re-read state counted as a replay, so a restarted viewer lost every running share until the contact's next state, at the latest the share's republication after midnight UTC | After a restart, a contact's latest state is read once more, and only it: an older one is still refused, and so is the latest one read again in the same run. Spec §8 and §12 say so, and the Python reference does the same. It amends a MUST of the spec, so it is marked **review** in §21, with what a restart still cannot know | `Sharing_ARestartedViewerReadsTheLatestStateOnceMore`, `Manager_AViewerRestartedDuringAShareFollowsItAgain`; 4 checks in `test_protocol.py` |
| 3 | The first time the dot's sheet opens after launch, its sides and bottom are not drawn | **Right**. The sheet is laid out whole: its lines and buttons sit on the same pixels as in the screenshot of the earlier dialog, so what is missing is drawn but not shown. The map is a SurfaceView, and the window tells the compositor which of its parts are transparent only at a layout pass; the compositor then shows the map there (Android 14's `ViewRootImpl`, `View`, `SurfaceView` and SurfaceFlinger). The bottom-sheet behaviour slides the sheet up from below the screen without a layout pass, so only what other views covered at the last pass was shown: in your screenshot, the part shown ends exactly where the map buttons' margins do, 8 dp in from the sides and above the navigation bar. Which view covered that part could not be told here. Nothing in this makes the first open special, so later opens may have shown it too | The sheet asks for a layout pass at each step of its movement | — |

The store's format did not change: this build reads the data of the builds since the fourth review.
The checklist's note on installing over the previous build still said otherwise, a leftover of the
fourth review; it is corrected.

**Tests now.** 102 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13,
and the map's tap test. The cross-implementation test passes 15 of 15 over strfry, the Python
reference's tests 309 of 309, the JVM tests 9 of 9, and lint finds no errors. The APK builds.

## 29. Seventh review of Phase 2 (2026-10-23)

You found that an update sent while the sharer is offline is lost. It was checked before anything
changed: right in all three cases, and seven more paths lost updates the same way. Your suggested fix
covers them all: a contact's current state goes again until a relay accepts it, and the app keeps
across restarts which contacts still wait for one. With your decisions below, each change in the core
has a test that fails without it (21 mutants, all caught).

| Your claim | Verdict |
|---|---|
| Offline at midnight UTC, Bob's map keeps the pre-midnight position until the next midnight's grant | **Right.** Reproduced with one phone's network switched off in the test harness: at 08:10 Bob's map still showed the 23:59 position, stale. Any other state from Alice to Bob would have ended it sooner; the next midnight's at the latest |
| Stopping offline, Bob's list still says she shares six hours later | **Right**, even with Alice back online and her app open. With a time limit, the share ended there on Bob's phone (§28); without one, only when Bob's app restarted on a later day |
| Starting offline, Bob sees nothing three hours later | **Right**, until the next midnight's grant |
| Doze makes the midnight case common on real phones | **In part.** The risk list says so (§13), but stock Android lets an app with a foreground service use the network in Doze (AOSP's `NetworkPolicyManager.isProcStateAllowedWhileIdleOrPowerSaveMode`: process states up to a bound foreground service), and a running share has one. On stock Android the loss needs the network itself to go: tunnels, flights, airplane mode overnight, weak coverage. OEM battery savers may still cut it. High all the same: every update made offline was lost, not only midnight's |
| There since the first implementation | **Right.** A state was published once; the relay pool reports a failure and keeps nothing. Only pairing steps went again, and only until the app restarted |

**Also lost, found while checking.**

1. A later time limit set offline: Bob's view ended at the earlier one while Alice shared for two
   more hours.
2. Someone added offline never saw the share, and the other recipients stayed on the old stream; the
   same when another recipient's time limit passed offline.
3. A dot colour chosen offline reached nobody.
4. Home relays changed offline: contacts learned the new list only the next day.
5. An answer to a contact's move, and the joiner's daily confirmation, waited for the contact's next
   state, or the next day.
6. Not offline: after the app was killed during a share, "Don't resume" sent nothing, so contacts saw
   the share until their app restarted on a later day.
7. Rarer: a pairing step sent offline was lost if the app restarted before the network came back;
   deleting a contact one shared with, offline, never told it; and an app left open offline past
   01:00 UTC, as on a night flight, missed a stop for good (reproduced: still listed at 02:00).

**Your decisions.**

| Question | Decision |
|---|---|
| How to keep that no relay accepted a state | In the stored record of which relays the latest state to a contact reached, empty until one did; answers and re-sends become one rule. It was to spare a change of the store's format, which the pairing steps below need anyway |
| CoMaps not running | A background job (WorkManager) that runs once there is a network, also after the app was killed or the phone restarted, and while the feature is off |
| "Don't resume" | Tells the recipients; until the user decides, they see the share as it was |
| Pairing steps | Kept in the store with their pairing, and sent again while the app is open until the invite expires |
| Deleting a contact one shares with | Its keys go at once, as before. Only states without a share, made then for that day and the next six, and the contact's relays are kept, until one is accepted and another on a later day. You asked what keeping the channel itself would risk: a phone taken from its owner would hold, for up to a week, the keys of a contact the user believes deleted (T7) |
| An app offline past 01:00 UTC | The sharer sends the end once more on a later day, by the background job if CoMaps is closed |

**What changed.** §21 has the rules (rows "States no relay accepted", "A share's end, once more",
"Deleting a contact one shares with", "A share interrupted by the process's death" and "The delivery
job"); spec §6.3, §8, §9, §11 and §13 the protocol's side, as SHOULDs. Beyond your finding:

- A share interrupted by the process's death needed a rule of its own: sending the current state again
  after the restart would have sent one without a share, ending the share before the user decided.
  Nothing goes to its recipients until then, not even a confirmation or a new relay list.
- A contact's move that arrives while the user's own latest state to it is still on its way is
  answered once that state has its answer.
- The core tells the app when something is next due, and a start alone sends nothing, so the daily
  ratchet job still connects nowhere.

**Store.** Its format is now 6, for the pairing steps and the deleted contacts' states: the data of
earlier builds is not read. Delete the live location data on both phones and pair again.

**Tests now.** 110 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13.
Eight are new: the three cases of your finding, the other paths, a restart in between, "Don't
resume", the next day's repeat, deleted contacts, pairing steps, and the relay pool saying that a
connection opened. Of 21 mutants of the new rules, 16 were caught at first; each of the other five
showed a gap, and the tests gained a check for it: a repeat sent on the same day, the repeat kept for
someone shared with again, an expired resume offer holding things back, a deleted contact's week, and
the due time while a state is on its way. The cross-implementation test passes 15 of 15 over strfry
and the Python reference's tests 309 of 309, unchanged: its test peer does not send again, as it
never did. The JVM tests pass 9 of 9, lint finds no errors and nothing in the new code, and the APK
builds with all 34 native methods exported. The delivery job has no test here, there being no phone or
emulator; the checklist has it, with the other offline cases.

## 30. Eighth review of Phase 2 (2026-10-24)

A read of the seventh review's code found one problem and three nits, and a run on a phone a bug in
the map. Each was checked before anything changed: all five hold, though the bug had another cause
than the one you guessed. Each change in the core has a test that fails without it (4 mutants, all
caught); the app's changes have none, there being no phone or emulator here, and are for the next
run on phones.

| # | Your finding | Verdict | Change | Test |
|---|---|---|---|---|
| 1 | Low: with the feature off, the delivery job never gives up | **Right.** The core counts a state as due until a relay accepts it, and the job retries whenever that time has passed, with WorkManager's back-off, which WorkManager caps at 5 hours (`WorkRequest.MAX_BACKOFF_MILLIS`, 18,000,000 ms in work-runtime 2.10.5, the version the app uses). Each run starts the core and connects to the contact's relays. With the feature on the same holds; see below | As you suggested: with the feature off, the job sends for a week after the feature was turned off, as long as a deleted contact is told; then it ends without starting the core. The time is kept with the switch; a feature turned off by an earlier build counts from the job's next run. Turned on again, the core sends what is due at once, as at every start | — |
| 2 | While the app is open, the job repeats the core's attempts | **Right**, and the count too: 56 reports here in two hours of refusals, with the app open; you counted 57. The core added a minute to the due time while a state was on its way, so that a job would not start while the core still waited for an answer. Each attempt moved the time forward and back again, two reports, and each report replaced the job with one due at once | The due time no longer moves while a state is on its way: it changes with what is due, never with an attempt, and the job waits for the relays' answers anyway (30 s at most). The job is there only while the app is neither on screen nor sharing: then the core runs and sends again by itself. Once the app leaves the screen the job is scheduled for the due time, so that it also covers the process ending and the phone sleeping. The core's delays use a monotonic clock, which stands still while the phone sleeps, whereas WorkManager wakes it. On screen, or sharing, the job is cancelled, and so is a run in progress. Each report of the core takes the job's place, that of a run in progress too, which then schedules nothing: the guard that held reports back during a run went with the reports at each attempt | `Manager_WhatRelaysRefuseGoesAgainEveryFiveMinutes`: no report in an hour of refusals. Two other tests check that the time does not move while a state, and a deleted contact's state, is on its way |
| 3 | Two retry triggers have no test: a 5-minute cap raised to an hour, and no retry when the app comes to the foreground, pass all 110 tests | **Right**: both mutants passed every test here too | Two tests. Relays that refuse for over an hour get the end of a share within five minutes of accepting again. And with the user's own relays down, so that no connection opens when the app comes to the foreground, coming to the foreground sends the end at once, not at the next attempt minutes away | `Manager_WhatRelaysRefuseGoesAgainEveryFiveMinutes`, `Manager_OpeningTheAppSendsWhatNoRelayAcceptedAtOnce` |
| 4 | The spec's obligations: the joiner's confirmation sits under the new bullet on sending again | **Right**, a slip of the seventh review | Back in the bullet before it, as the exception to its rule | — |
| 5 | "Center" on the dot's sheet and "Show on the map" in the contact's details do nothing while the map follows the user's position; the dots may reuse the position mark's code | **Right**, but not for that reason: the dots are user marks in a layer of their own (`libs/map/live_location_marks.*`), with nothing of the position mark. While the map follows the position ("locate me", or turning with the heading), drape moves the map back to it at every new position (`MyPositionController`). Upstream stops following before it moves the map to a bookmark, a track, a search result or a place from a link (`Framework::StopLocationFollow`); these two buttons did not. Of the feature's code, only they move the map: a tap on a dot opens the sheet where the map is, and the sheet only tells the map how much of it the sheet covers, as the place page does | Both stop following first, through one helper, then move the map. During navigation the map follows the position again after 20 s untouched, as after any move | Checklist |

**With the feature on.** The job still never gives up then, for a contact whose relays are gone or
refuse for good: one short run every 5 hours at most, for as long as no relay accepts. It was left
so. With the feature on, the user has asked for work in the background, and a contact whose relays
take nothing hears from no one through them until it moves to others, which its app announces; the
state then goes there at once. Giving up could leave a contact's app showing a share that has ended,
should its relays come back. And a week counted by the core needs to know since when a contact's
states have gone unaccepted, which the store does not keep: a new format, and pairing again on both
phones. Counted by the job alone, it would leave the core trying while the app is open. Your call.

**Tests now.** 112 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13.
Two are new; two others check more. The 4 mutants of this review's rules are all caught: the
5-minute cap raised to an hour, no retry when the app comes to the foreground, and the minute added
while a state is on its way, for a contact and for a deleted one. The cross-implementation test
passes 15 of 15 over strfry, and the Python reference's tests 309 of 309, unchanged. The JVM tests
pass 9 of 9, lint finds no errors, and the APK builds. The store's format did not change: this build
reads the seventh review's data.

## 31. Ninth review of Phase 2: a review by a third party (2026-10-25)

You had the whole PR reviewed by a third party with relevant expertise. Each finding was checked
against the code, against Android 12 to 14's own source and with running tests before anything
changed. Most hold, but the ranking does not: the most serious live bug was filed as a latent one
(R2), and five of the smaller items do not hold. Each change in the core has a test that fails
without it (31 mutants, 30 caught; the one left is explained below). The app's changes have no
test, there being no phone or emulator here, and are for the next run on phones.

| # | The review's finding | Verdict | Change | Test |
|---|---|---|---|---|
| M1 | Major: the sharing service can stop before it goes foreground, which crashes the app | **The crash holds; its triggers do not.** The service's early exits stopped without going foreground, and Android crashes an app whose service, started to go foreground, stops before it does (`ActiveServices`). But every caller starts the service only after the core accepted the share and after checking location and notifications; the core refuses a time limit already past, a failed write ends no share, and a share started below the battery level runs until the battery has been above it. A race of milliseconds remained: a share ending between the start and the service's first command | The service goes foreground first, with the title alone when the share has ended meanwhile, then checks, and stops with its latest start's id, so that a start meanwhile, for a new share, keeps it. Android clears the requirement as soon as `startForeground()` passes its first checks, so a later refusal, such as no location permission, stops it without a crash | Checklist |
| M2 | Major: "Delete all live location data" with the feature off can race a core still running and bring the store back | **Holds.** Java deleted the file and the Keystore keys without the native side, while a core could still be sending: a stop's ends, up to 30 s after the feature was turned off, or the delivery job's. Its next save wrote the file again: usually under the key just deleted, so that the next start offered to delete unreadable data; but if the core erased a key meanwhile (the daily erasure at 01:00 UTC, an invite expiring), the save wrapped the data under a new key, readable again, contacts included. Since the eighth review, turning the feature off starts the job at once, so "turn off, then delete" lands in that window | Deleting with the feature off cancels the delivery job and runs on the core's thread, which every access to the store goes through: after whatever it is doing, a core still sending goes without writing again, then the file and the keys go. Your decision: at once, though contacts may then not learn that a share stopped just before has ended | Checklist |
| R1 | A relay that never sends EOSE is never judged, and can stay the listening relay | **Holds.** Without EOSE the echo check never starts: a deaf relay that left its REQ unanswered kept the listening role for good, where one that answered was left within 15 s | A REQ without EOSE after 15 s fails the connection, as a missing OK does: the relay backs off, the subscriptions move, and they come back once it answers again. Not "deaf", as first proposed: that mark ends only when a post comes back, which a relay that never sends one back never does, so one slow EOSE would have demoted it for the rest of the run | `RelayPool_AReqWithoutItsEoseFailsTheRelay` |
| R2 | The same event published twice before its first OK: the first publication never completes, and a healthy connection fails | **Holds, and in every pairing, not one refactor away.** The joiner's first step was published, then again as the pairing's subscription started. The second copy took the first's place: the first never completed, all three of the joiner's connections failed 25 s later for want of an OK that had come (all three relays backed off at once), and the pool counted a publication pending for the rest of the process, so that each stop and each run of the delivery job waited its full 30 s. The pairing itself went on; the "no OK" lines had been in the tests' logs | The pool sends an event once over a connection while its OK is pending, and gives that OK to every publication of it. The core does not send a pairing step again while it waits for its relays' answers | `RelayPool_AnEventPublishedAgainOnItsWayWaitsForTheSameOk`, `Manager_APairingStepNoRelayAcceptedGoesAgain` |
| R3 | A relay's back-off is forgotten whenever a connection to it opens | **Holds**: a relay that drops each connection as it opens got 57 connections a minute (3,331 an hour), and each moved the listening subscription and back | The back-off starts over once the relay answers a publish or a REQ. After one it left unanswered, only an answer of that kind counts, so that a relay that answers publishes and never ends a REQ, which the EOSE deadline now fails, or the reverse, keeps backing off as well. About ten connections in ten minutes now | `RelayPool_ARelayThatDropsEveryConnectionBacksOffFurther`, `RelayPool_ARelayThatAnswersNoPublishKeepsBackingOff`, `RelayPool_AnAnswerStartsTheBackOffOver` |
| R4 | An event counts as come back before it is verified | **Holds, with little effect**: a relay that sends back only broken copies passed the check. The record of relays that sent one back only makes a relay subject to the check, so a false credit cannot spare it later, and 32 broken events fail the connection anyway | A copy counts once it matches the REQ and its id and signature verify | `RelayPool_OnlyAnIntactCopyCountsAsSentBack` |
| R5 | Duplicates are told by the text of the OK, which NIP-01 does not fix | **Holds in part.** NIP-01 defines the `duplicate:` prefix, but asks for a prefix only on a refusal: a duplicate accepted with an empty message marked the relay deaf. Only a pairing step sent again after a lost OK could do that, over a new connection, since the missing OK had failed the old one; ids kept per connection, as suggested, would not have seen it | Only the listening subscription judges, as only it moves away from a deaf relay; the only posts it asks for are the share's own, never sent twice. A pairing's steps still count as come back, but never against a relay. A post sent again over its connection is not judged either | `RelayPool_AnEventSentAgainIsNotJudged` |

The smaller items and the nits:

| The review's finding | Verdict | Change |
|---|---|---|
| A negative `until` or `eta` is accepted | **Does not hold**: an integer is at least 0 unless said otherwise (`json.hpp`), in the Python reference too; negative values run through it are refused | — |
| `requireContext()` unguarded in the permission callback | **Does not hold**: AndroidX delivers that result only to a started fragment | — |
| The indicator's icon does not forward `setTint` | **Does not hold**: `Drawable.setTint` calls `setTintList`, which the icon overrides | — |
| `LiveLocation` lacks a class-level `@Keep` | **Does not hold**: release builds shrink without renaming, and each member that native code calls is `@Keep`. A release build's shrinker (R8), run here for the first time, keeps them all, the 35 native methods and the 8 that native code calls back | — |
| "min" and "h" written in English | Holds | The units of route times, which upstream translates |
| "?" for a recipient without a contact | Holds, for a moment while a contact is deleted | Left out of the names |
| A share that waited for the notification settings does not start on return | Holds | It starts on return, if its notification can be seen now |
| The QR code has no description | Holds | "Invite code to scan" |
| A failed `NewString` calls into Java with an exception pending | Holds, when out of memory | Each such call is skipped then |
| The map's offer to resume passes recipients whose end has passed | Holds, without effect: the core refuses the share, and the map falls back to Manage sharing, which leaves them out | — |
| `start()` blocks the main thread; `deliver()` waits up to 30 s | As described. Left: an asynchronous start changes how a store error reaches the screens, which phones should measure first; the wait sleeps between checks rather than spinning | — |
| An unknown pairing stage reads as cancelled; no `@MainThread` on the getters | True, but unreachable: the data comes from the same APK, and no other thread reads it | — |
| JNI casts | Benign, as the review says | — |
| The relay pool's nits: a REQ sent after its CLOSE when the connection was still opening, notices keeping a connection open, closed connections parked without cleanup, junk under REQ ids never sent costing nothing | All hold | All fixed. Events for one of a connection's last 16 REQs closed are not junk: they may have left before the relay had the CLOSE (tests: `RelayPool_ASubscriptionEndedBeforeItsConnectionOpensIsNeverSent`, `RelayPool_NoticesDoNotKeepAConnectionOpen`, `RelayPool_EventsForNoReqCountAgainstTheRelay`) |
| The modulo bias of the code | As described, though 2³² mod 10⁶ is 967,296, not 7,296: about 0.02 %, negligible either way | — |
| Gaps in the tests | Hold: no tests of the app (no emulator here), ASCII-only JVM fixtures (the C++ UTF-16 conversion has tests of its own), the desktop WebSocket covered only by the cross test | The relay pool's missing scenarios are added: overlapping publishes, a relay without EOSE, connections dropped as they open |

**A week without an accepted state.** The eighth review left a question open (§30): with the feature
on, what no relay accepted went again without end, the job at most every 5 hours. You asked whether
the store format it needed would cost anything elsewhere. It does not: nothing on the wire changes,
the Python reference does not read the store, the desktop peer keeps a store per run, and nobody has
data to keep before the first release (§26). Pairing again on both phones is the whole cost. It is a
modest improvement, made so as to keep what retries without end gave:

- The week counts from the first of a contact's states that no relay accepted since, not from each
  change: the joiner's daily confirmations and the daily new relay list would otherwise start it over
  for ever, for a contact that never receives.
- After the week, its states still go whenever the app is on screen. A contact whose relays come
  back learns that a share ended the next time the user opens CoMaps; only the core in the background
  and the delivery job stop.
- The week starts again when the contact names other relays, or the user allows one of its relays:
  the way out you named stays.
- The week counts while the phone is offline too. A phone offline for more than a week sends the
  change when the user next opens CoMaps.
- The job's week with the feature off (§30) stays as it was.

**The mutant left.** The core's check that a pairing step on its way is not sent again: with the
pool's own fix, the second publication costs nothing and changes nothing a test can see. It stays,
so that the core does not rely on the pool for it.

**Tests now.** 125 C++ tests of the core pass with clang 18 (unity and non-unity builds) and GCC 13;
13 are new. Of the 31 mutants of this review's rules, 30 are caught, and so are the 24 of the
seventh and eighth reviews. The cross-implementation test passes 15 of 15 over strfry, with the
EOSE deadline and the new back-off against a real relay, and the Python reference's tests 309 and
200, unchanged. The APK builds; all 35 native methods are exported, one of them new. The JVM tests
pass 9 of 9, and lint finds no errors. The store's format changed: this build reads no earlier
build's data, so delete it on both phones and pair again.
