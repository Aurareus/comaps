# Live location sharing: design (Phase 1, for review)

Status: **draft for review**, 2026-10-09. No feature code has been written. The normative protocol
is in [LIVE_LOCATION_PROTOCOL.md](LIVE_LOCATION_PROTOCOL.md) ("NLL v1"). The reference implementation,
test vectors and the relay test harness are in
[`tools/python/live_location/`](../tools/python/live_location/). The decisions that need your
sign-off are collected in [§14](#14-decisions-to-sign-off).

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
14. [Decisions to sign off](#14-decisions-to-sign-off)
15. [Answers to the Phase 1 questions](#15-answers-to-the-phase-1-questions)

## 0. Summary

- **What.** You pair with someone once, in person by QR code or remotely by link. From then on
  either of you can share your live location with any set of paired contacts, for a fixed time or
  until stopped. Anyone sharing with you appears on your map as a named dot that follows them.
- **Transport.** Ordinary public Nostr relays (or your own), used as dumb, untrusted, interchangeable
  pipes. Every event goes to all of a user's relays (default: three), so any single relay, or any two
  of three, can fail.
- **Privacy.** Relays never see positions, names, contact lists or any long-lived identifier.
  - There are **no identity keys at all**. Every event is signed by a pseudonymous key: per invite,
    per contact-direction per day, or per share stream.
  - Every payload of a class is padded to the same size.
  - What remains visible to relays is network metadata (IP addresses, timing, volume), documented in
    [§3](#3-threat-model).
- **Retention.** Relays hold only the *latest* position of an active share (an addressable event).
  It expires 15 minutes after publication, or sooner when the share ends. Viewers keep only each
  contact's latest position.
- **Revocation.** Each share uses a random stream key. Removing a recipient (or a share expiring)
  starts a new stream that only the remaining recipients are told about. The removed person can
  neither find nor decrypt anything after that.
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
- **Needs you.** The decisions in [§14](#14-decisions-to-sign-off). The big ones:
  - D2: protocol structure.
  - D3: latest-position retention.
  - D4: viewer-driven update rate, which trades a little metadata for a lot of battery.
  - D11: when a viewer goes online.
  - Device testing will be yours, because this environment cannot run an emulator.

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
  plain `SharedPreferences` (not encrypted), see [§10.4](#104-key-storage-at-rest).
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
| 1 | Consent and visibility | Off by default behind a feature flag. Sharing starts only from the share sheet, with explicit recipients and duration. A foreground-service notification (with Stop) and an in-app indicator are shown while sharing. No silent mode exists. Recipients have no message that could start, extend or alter a share; the protocol has no such message type at all. |
| 2 | Recipient control | Per-recipient `until`, Stop per recipient or all. Every membership change rotates the stream, so revocation is cryptographic and immediate (§4.4). |
| 3 | Confidentiality incl. metadata | No identity keys. Event keys are pseudonyms rotated per invite, per day or per stream. No `p` or `g` tags. Payloads are padded per class. What remains (IP, timing, volume) is analysed in [§3](#3-threat-model). |
| 4 | Decentralisation | No server of ours. Any NIP-01 relay works. Publishing goes to all (default 3) relays, and the list is user-configurable, including self-hosted relays. Measured in [§6](#6-transport-evaluation-and-relay-test-results). |
| 5 | Minimal retention | Addressable "latest only" events with NIP-40 expiry: 15 min for positions, end of day + 1 h for channel state. No NIP-09 deletion requests, because relays keep those forever (§6.3). Viewers store only the latest position per contact. |
| 6 | Inert unless used | No initialisation without the flag. No connection without a paired contact. Then connections only while sharing, while pairing, or while the app is in the foreground and has contacts (decision D11). |
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
| T1 | **A relay operator** (each relay) | **Network metadata:** the IPs of publishers and subscribers, connection times, events per pseudonymous key, update cadence (moving vs. stationary), how many connections subscribe to a stream key, that the kinds belong to this protocol, and a coarse IP geolocation of both ends. **Correlation:** when sharer and viewer use the same relay, it can link the sharer's IP and the viewer's IP through a shared event key. **Active attacks:** drop, delay or replay events. | Read positions or names. Link event keys across days, invites or streams except by IP/timing. Forge or alter events (signatures, MACs). Replay an old grant or location: `seq` ordering stops it. Learn group membership beyond "these IPs follow that key now". |
| T2 | **Colluding relays or a global passive observer** | Everything in T1, correlated across relays and over time. With stable IPs, a long-term IP-level contact graph. | As above. Content stays confidential. |
| T3 | **An on-path network observer** (ISP, Wi-Fi) | The relay hostnames (TLS SNI), timing and volume, hence that you use Nostr relays and roughly when you share. | Any event content. TLS hides even the pseudonyms. |
| T4 | **A revoked or expired recipient** | The old stream key, so updates published *before* revocation if it recorded them. It sees its channel state change to "not sharing". | Find the new stream (new random key), decrypt it, or learn the remaining recipients. |
| T5 | **A malicious current recipient** | Your positions (by design). It can re-share them out of band (unpreventable). | Forge your positions to other recipients: the stream is signed by a key only you hold. Learn who else receives the share: grants are pairwise. Start, extend or alter your share. |
| T6 | **Someone who intercepts an invite** (photographed QR, compromised messenger) | **Race** the intended person and pair as an impostor; the inviter sees an unexpected request, and the real person's attempt fails. **Sit in the middle** of both handshakes; the two screens then show different codes, with a 10⁻⁶ chance of a coincidental match thanks to the commitment. Mitigations: inviter confirmation, codes on both screens, single-use invites, expiry (10 min for QR). **Passive interception** (knowing the PSK and recording relay traffic) reveals only the inviter's name and relays, carried in Noise message 1 under PSK-only protection. The joiner's message 2 and everything after it are protected by `ee`. | Learn channel keys from a pairing it did not actively complete: `ee` Diffie-Hellman. |
| T7 | **Device thief / forensic at rest** | Nothing from a locked, file-based-encrypted (FBE) device. With an unlocked device: current keys and the latest position per contact. | Past channel keys (ratchet) and past streams (erased). No location history is kept anywhere. |
| T8 | **Malware or root on the device** | Out of scope: it can read everything the app can. | — |
| T9 | **CoMaps project / app distribution** | Out of scope: it ships the code. It plays no role in operation; no CoMaps server is involved. | — |
| T10 | **Other relay clients** (scrapers) | The same as T1, minus IP addresses. | — |

Residual leaks worth stating plainly (they go into the user-facing explanation screen,
[§11.6](#116-what-relays-can-see-one-screen)):

- **IP addresses.** Inherent to any internet service. Tor or proxy support is out of scope for v1,
  but not precluded (OkHttp supports proxies).
- **Timing and cadence.** Update times reveal when you are moving; with decision D4 they also reveal
  when someone is watching you. Constant-rate cover traffic would hide this at a large battery cost
  (not proposed).
- **Viewer counts.** A relay can count the connections subscribed to a stream.
- **Protocol fingerprint.** The kind numbers identify the protocol.

## 4. Protocol overview

Full byte-level detail: [LIVE_LOCATION_PROTOCOL.md](LIVE_LOCATION_PROTOCOL.md). In short:

### 4.1 Pairing

1. A shows a QR code (or sends a link) containing a 32-byte one-time secret, an expiry and A's
   relays (91 bytes, a 141-character link).
2. B's app derives a one-time "rendezvous" Nostr key from the secret, and publishes a commitment to
   its fresh Noise key on A's relays.
3. A's app answers with Noise `NNpsk0_25519_ChaChaPoly_SHA256` message 1; B's app replies with
   message 2, which opens the commitment. Names and relay lists travel encrypted inside the handshake.
4. A's app shows "Bob wants to connect — code 779 997" and asks A to accept. B's app shows the same
   code.
5. A's decision is sent as the fourth message. Both apps derive two per-direction channel roots from
   the handshake.

The commitment makes the 6-digit code meaningful: without it, a man in the middle who intercepted the
invite could try keys offline until both screens show the same code (§5).

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

- Removed recipients get a state without a grant, and the old stream gets an `end`.
- Recipients also enforce `until` locally.
- So a removed recipient cannot read later updates, cannot find the new stream, and stops seeing
  the share at once.

### 4.5 Watch signals (D4)

While a viewer has the map open, it sends a small ephemeral, encrypted "watching" signal to the
sharer about once a minute. The sharer then sends every fix instead of one per minute. This is what
reconciles "follows within ~5 s" with an acceptable battery cost.

## 5. Cryptographic construction and rationale

| Need | Choice | Why |
|---|---|---|
| Nostr event ids and signatures | SHA-256 and BIP-340 Schnorr via **libsecp256k1** | Mandatory for Nostr (relays verify). libsecp256k1 is Bitcoin's reference implementation, the most scrutinised secp256k1 code there is. |
| Pairing | **Hash commitment, then Noise `NNpsk0_25519_ChaChaPoly_SHA256`** with the invite secret as PSK | A standard handshake pattern with a published formal analysis ([Noise Explorer: NNpsk0](https://noiseexplorer.com/patterns/NNpsk0/)) and official vectors (cacophony). The PSK authenticates both sides. Ephemeral `ee` Diffie-Hellman keeps later messages secret even if the invite leaks afterwards. The handshake hash gives the 6-digit code. The commitment, the joiner's hash of its ephemeral key sent first, stops a man in the middle from grinding keys to make the codes match; Matrix SAS, ZRTP and Bluetooth numeric comparison use the same technique. X25519 and ChaChaPoly come from Monocypher (already in tree). |
| Channel keys | HKDF-SHA256 hash chain advanced per UTC day; per-day signing key and NIP-44 key | Simple forward secrecy (a seized device cannot decrypt earlier days' grants). Pseudonyms change daily. No extra round-trips: both sides derive the day's keys from the clock. |
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
  (paid). No rate limiting at 0.2 events/s sustained or 5 events/s in bursts. The only refusals were
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
  relay_pool     connections via an abstract WebSocket interface; publish/OK tracking,
                 subscriptions, dedupe, reconnect/backoff, relay health
  store          contacts, chains, streams; one file, encrypted with a data key
  manager        the state machine: pairing, sharing, viewing, timers, cadence policy;
                 callbacks for UI and map; runs on its own task loop
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
| `MwmActivity` | menu entry, indicator, intent processor | ~10 lines |
| settings (prefs XML + fragment) | experimental toggle | ~10 lines |

### 8.4 Feature flag

A runtime preference "Live location sharing (experimental)", default **off**. While off, nothing in
the feature is constructed: no library init, no threads, no files, no network. When it is switched
off, all shares stop and connections close. Contacts are kept until deleted, and the screen offers
"delete all live-location data".

### 8.5 Persistence

One file, `live_location.dat`, in Android's `noBackupFilesDir`:

- it holds contacts, chain keys, sequence numbers and the active stream;
- it is encrypted with XChaCha20-Poly1305 (Monocypher) under a 32-byte data key;
- that data key is wrapped by an Android Keystore AES-256-GCM key;
- it is written atomically (tmp + rename) after every key change, so ratchet erasure is durable.

Viewers persist only the latest position per contact. The sharer persists no positions at all.

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

Estimated budgets for one hour, sharer side, three relays. These are estimates to be replaced by
the measurements the DoD requires:

| Scenario | Data | Battery (very rough; GNSS ≈ 0.1 W, LTE tail ≈ 0.5–1 W for ~10 s per send) |
|---|---|---|
| Constant 5 s cadence (no D4) | ≈ 2.5 MB up+down | radio never idles: **≈ 4–8 %/h** on a 15 Wh battery |
| D4, watched the whole hour | ≈ 2.5 MB | as above while watched |
| D4, never watched, walking | ≈ 0.2 MB | **≈ 1–2 %/h**, GNSS-dominated |
| D4, never watched, stationary | ≈ 0.05 MB | < 1 %/h |
| Viewer, map open, 3 relays | ≈ 2 MB down (each update arrives once per relay) | screen dominates |

The cost of D4 is metadata (see T1): relays can see that a viewer's signal is followed by faster
updates on some stream. Both sides get a setting to turn it off: viewers can stop asking for live
updates, sharers can refuse boosts.

### 10.4 Key storage at rest (question 5)

The existing `SecureStorage` is **plaintext `SharedPreferences`** (sandbox protection only), and on
desktop it writes into `settings.ini`. Not suitable on its own. Proposal (part of D6):

- **Wrapping key.** A non-exportable AES-256-GCM key in **Android Keystore** wraps a random 32-byte
  data key. The key is hardware-backed where available, with no user-authentication requirement,
  because sharing must work with the screen locked.
- **Data file.** The data key encrypts `live_location.dat` with XChaCha20-Poly1305 (§8.5).
- **Backups.** The file lives in `noBackupFilesDir`, so it is excluded from every backup without
  touching the backup rules. A restored backup therefore has no live-location state: re-pairing is
  required, and key backup is out of scope.
- **Limitation.** This protects against offline extraction (backups, ADB pulls, file-level forensics
  of an unlocked image). It does not protect against code running as the app; see T8.

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
2. B scans the QR with any camera or QR app that opens links (Google Camera/Lens, GrapheneOS camera,
   Aperture), or taps the link, or uses **Paste invite** on the same screen. B sees "Connecting…".
3. Within seconds (three relay round-trips), B sees "Waiting for Alice to confirm — code
   **779 997**".
4. A sees "Bob wants to connect — check that Bob's screen shows **779 997**" → [Connect] / [Decline].
5. B: "Connected with Alice". Both see the contact in their lists. The code stays visible in the
   contact details as "Verify".

### 11.3 Sharing

Live location → **Share my location** → pick contacts (multi-select) and a duration (15 min, 1 h,
8 h, until I stop) → **Start**.

- Permission prompts: location (fine) if missing; notifications on API 33+.
- Notification: "Sharing live location with Bob and Carol · until 18:30" with **Stop**.
- On the map, an indicator chip shows "Sharing with 2". Tapping it opens **Manage sharing**:
  per-person stop, add people, extend, stop all.
- Extending or adding someone is only ever done by the sharer.

### 11.4 Viewing

- Contacts sharing with you appear as coloured dots with their name label, shown up to a contact
  limit.
- Each dot fades to grey when its update is over 2 minutes old ("last seen 7 min ago" on tap). It
  disappears when the share ends or `until` passes.
- Tapping a dot opens a small sheet: name, last update, accuracy, "Center", "Hide".
- With D4, opening the map makes the sharer's dot go live within a few seconds.

### 11.5 Contacts and settings

- Contact list: name, status ("Sharing with you until 18:30", "You share until …"), rename,
  verify code, delete. Deleting a contact also stops any share with them.
- Relays: list, add, remove, and a reachability test. A warning appears when fewer than two relays
  work.
- Toggles: "Request live updates when viewing" and "Allow viewers to request live updates" (D4),
  and the low-battery stop threshold.

### 11.6 What relays can see (one screen)

Draft text, also a DoD item:

> **How live location stays private**
>
> Your location is encrypted on your phone. Only the people you choose can decrypt it.
>
> It travels through relays: independent servers run by volunteers or companies (you can pick
> your own). Relays **cannot** see your location, your name, who your contacts are, or who you
> share with.
>
> Relays **can** see:
>
> - your phone's internet address, which reveals your rough region and your provider;
> - when you send updates and how often (moving phones send more often);
> - that the app uses this live-location feature;
> - roughly how many people are watching a share.
>
> Relays keep only your latest encrypted position, and only until 15 minutes after it was sent.
> Your location is never sent while you are not sharing. While the app is open and you have
> contacts, it asks the relays whether anyone is sharing with you. People you stop sharing with
> cannot read anything you send afterwards.

## 12. Test plan

- **Unit (C++, `live_location_tests`)**:
  - every primitive against its published vectors: NIST SHA-256, RFC 5869, NIP-44 v2, BIP-340, and
    the Noise cacophony vector;
  - every NLL vector reproduced byte for byte from `nll1_vectors.json`;
  - the receiving rules, including tampering, replay, expiry, wrong key and oversize;
  - the ratchet, epoch boundaries and clock skew;
  - store round-trip and erasure;
  - the cadence policy.
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
  - pairing time (stopwatch);
  - follow latency (screen recording of both phones, or a timestamp overlay);
  - stop and revocation (test peer);
  - time-limited end;
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
| Stalkerware misuse | No silent mode, a persistent notification, sharer-only control, no remote start or extend |

## 14. Decisions to sign off

My recommendation comes first in each row. Rows marked † are ones I would simply proceed with
unless you object.

| # | Decision | Recommendation | Main alternative |
|---|---|---|---|
| **D1** | Transport | **Nostr relays** (§6.1) | SimpleX SMP later as a second transport |
| **D2** | Protocol structure | **No identity keys; Noise pairing; daily-ratcheted pairwise channels; sender-key stream rotated on every membership change** (§4, §5) | Per-recipient NIP-44 copies (simpler, but O(n) traffic); MLS/Marmot (identity-bound onboarding, heavy) |
| **D3** | What relays keep | **Latest position only (addressable, 15-min expiry)**, so a viewer sees the position immediately on opening the map | Ephemeral only: nothing stored, but the viewer waits for the next update, minutes when idle under D4 |
| **D4** | Update policy | **Viewer-driven live mode** (§10.3): every fix while watched, ≥ 50 m / 5 min otherwise; toggles on both sides | Constant 5 s cadence: simpler, no watch metadata, roughly 3–5× the battery |
| D5 | Default relays | **nos.lol, nostr.mom, relay.nostr.net** (soak results in §6.3) | relay.primal.net, nostr.data.haus |
| D6 | Feature minimum Android, key storage | **API 24+; Keystore-wrapped data key; file in `noBackupFilesDir`** | API 21+ with a custom TrustManager |
| D7† | WebSocket library | **OkHttp 4.12** | Java-WebSocket (smaller, less proven) |
| D8 | QR scanning | **No in-app scanner in v1**: system camera or QR app opens the link, plus "Paste invite". No camera permission, no 1.5 MB | ZXing + CameraX in-app scanner |
| D9† | SHA-256 source | **Shim over libsecp256k1's internal implementation** | Vendor Bitcoin Core `crypto/sha256.cpp` (MIT) |
| D10† | Names | **Protocol "NLL v1", labels `nll1:`, kinds 30484/20484, link `comaps://live/pair#…`** | Anything you prefer |
| **D11** | When a viewer connects | **While the app is in the foreground and at least one contact exists**, to discover shares. Never in the background | Only while a "Live locations" map layer is switched on (stricter, but you would not notice a new share) |
| D12† | Location payload | **lat, lon, acc, ts, spd, brg, alt; `low` battery flag; `nav` reserved** (PoC fields) | Leave out `low`/`alt` |
| D13† | Pairing confirmation | **The inviter always confirms, with the code shown** | Auto-accept for in-person QR |
| D14† | Strings | **A new English-only `strings_live_location.xml`**, translated later via the normal pipeline | Add to the main strings source now (rebase conflicts) |

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
