# NLL v1: private live location over Nostr (protocol specification)

Status: **draft, design approved** (2026-10-10). The decisions in
[LIVE_LOCATION.md](LIVE_LOCATION.md#14-decisions) were signed off together with the review fixes
listed in [LIVE_LOCATION.md §16](LIVE_LOCATION.md#16-review-changes-2026-10-10). The
implementation may still change details; every change goes through this document and the vectors.

- Reference implementation: [`tools/python/live_location/nll/`](../tools/python/live_location/nll/)
  (mirrors this document section by section).
- Test vectors: [`tools/python/live_location/vectors/nll1_vectors.json`](../tools/python/live_location/vectors/nll1_vectors.json),
  regenerated deterministically by `make_vectors.py` (see [§15](#15-test-vectors)).
- Design rationale, threat model and evaluation: [LIVE_LOCATION.md](LIVE_LOCATION.md).

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

Two people **pair** once (QR code or link, then a commitment plus a Noise handshake over relays).
Pairing gives each pair of devices two one-way **channels**. A channel is a chain of keys that advances once per UTC day
and cannot be run backwards. While a user shares their location they publish one **stream**: a single
replaceable Nostr event holding their latest encrypted position, signed by a random key that only they
hold. Each recipient learns the stream's public key and decryption key through its channel (a
**grant**). Revoking anyone means starting a new stream and granting it only to the remaining
recipients.

There are no long-term identity keys. Event keys, tags, content and sizes are not derived from, or
linkable to, a person, a device or a contact relationship. What does link them is network metadata:
IP addresses, timing, and the keys that one connection uses together. §11 limits the last to a single
day. The design doc's threat model spells out what each party can learn.

## 2. Conventions

- `||` is byte concatenation. `u8`, `u32be` are unsigned integers (big-endian for `u32be`).
- `label(x)` is the ASCII string `nll1:` followed by `x`, e.g. `label("ck") = "nll1:ck"`.
- Times are Unix seconds (UTC) unless a field says milliseconds.
- `epoch(t) = floor(t / 86400)` (the UTC day); `epoch_end(e) = (e + 1) * 86400`.
- `base64` is RFC 4648 §4 with padding; `base64url` is RFC 4648 §5 without padding.
- Hex is lowercase.

## 3. Primitives

| Name | Definition |
|---|---|
| `SHA256`, `HMAC-SHA256` | FIPS 180-4, RFC 2104 |
| `HKDF-Extract(salt, ikm)`, `HKDF-Expand(prk, info, L)` | RFC 5869 with SHA-256 |
| BIP-340 | Schnorr signatures over secp256k1, x-only public keys (as required by NIP-01) |
| NIP-44 v2 | [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) from step 2 onward ("generate nonce" … "base64"), with the conversation key given by this spec instead of ECDH. Plaintexts are limited to 65535 bytes (this profile never uses the extended length prefix). |
| Noise | `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, Noise Protocol Framework revision 34 |
| CSPRNG | the operating system's secure random generator |

`derive_secp_key(prk, purpose)`: for `ctr = 0 … 255`, let
`cand = HKDF-Expand(prk, label(purpose) || u8(ctr), 32)`; return the first `cand` with
`1 ≤ int(cand) < n` (secp256k1 group order). The loop practically never runs twice.

## 4. Nostr usage

| Kind | Range | Used for |
|---|---|---|
| `30484` | addressable (NIP-01) | pairing messages, channel state, location stream |
| `20484` | ephemeral (NIP-01) | viewer→sharer signals |

The numbers are provisional and not registered (see the design doc, decision D10).

Every NLL event is a normal NIP-01 event (id = SHA256 of the canonical serialization, BIP-340
signature). Additional rules:

- Kind `30484` events MUST carry exactly the tags `["d", <value>]` and `["expiration", <decimal>]`
  (NIP-40), in that order. The `d` value is `""` except for pairing messages (§6).
- Kind `20484` events carry no tags.
- A sender MUST make `created_at` strictly increase per event pubkey: relays keep only the addressable
  event with the highest `created_at` (lowest id on ties), so two updates in the same second could
  otherwise lose the newer one. Senders use `max(now, previous_created_at + 1)`.
- No other tags are used. In particular, no `p` tags and nothing derived from a user's identity.

## 5. Plaintext encoding

Every encrypted payload is a UTF-8 JSON object with a string member `"t"` (its type), right-padded
with ASCII spaces (0x20) to **exactly** the size of its class:

| Class | Size | Messages |
|---|---|---|
| control | 512 bytes | `pair1`, `pair2`, `pair3`, `state` |
| stream | 256 bytes | `loc`, `end`, `watch` |

Senders MUST pad; a message that does not fit its class MUST NOT be sent. Receivers MUST accept any
length up to 512 bytes, parse the JSON (trailing whitespace is legal JSON) and ignore unknown members.
Receivers ignore messages whose `"t"` they do not know.

Consequence: all NIP-44 payloads of one class have the same length (432 base64 characters for the
stream class, 772 for the control class) whatever their contents.

Common field limits:

- Relay lists contain 1–4 URLs of at most 64 bytes each.
- Every URL is `wss://`. The only exception is `ws://` to the host `localhost`, `127.0.0.1` or
  `[::1]`, for local test relays. Senders MUST NOT send, and receivers MUST reject, any other
  `ws://` URL: without TLS, an on-path observer would see the event keys and contents that TLS
  hides (design doc, threat T3).
- Names are at most 64 bytes.

## 6. Pairing

### 6.1 Invite

```
invite = u8(1)                      version
      || psk[32]                    from the CSPRNG
      || u32be(expires_at)          invite lifetime end
      || u8(n)                      1 ≤ n ≤ 4
      || n × (u8(len) || url[len])  the inviter's home relays (§11)
link   = "comaps://live/pair#" || base64url(invite)
```

The invite is shown as a QR code of `link` or sent as `link` over any channel. Example: 91-byte
invite, 141-character link. Each invite is **single-use** (§6.3). The inviter forgets `psk` when the
pairing ends or the invite expires.

QR invites live 10 minutes and link invites 24 hours. Every pairing event is stored on the relays
until the invite expires, so the two apps need not be open at the same moment. Each step is taken
when the app that owes it is next open; implementations keep the pairing state (encrypted, design doc §8.5)
until the pairing ends or the invite expires.

### 6.2 Rendezvous key

Both sides derive a key from the PSK, used only to sign the pairing events:

```
rv_sk = derive_secp_key(HKDF-Extract(salt = "nll1:rv", ikm = psk), "rv-sign")
```

### 6.3 Handshake

The **inviter** (who showed the invite) is the Noise **initiator**; the **joiner** (who scanned or
opened it) is the **responder**.

- Noise prologue: `label("pair") || u8(1) || u32be(expires_at) || u8(n) || relays…`, i.e. the invite
  without the PSK, which Noise mixes in itself.
- All four messages are kind `30484` events signed by `rv_sk`, with tags
  `[["d",<step>],["expiration",expires_at]]`, published to the inviter's home relays.
- Both sides subscribe to `{"kinds":[30484],"authors":[rv_pk]}` there.

| Step | `d` | From → to | Content |
|---|---|---|---|
| 0 | `"0"` | joiner → inviter | `base64(SHA256(label("commit") \|\| e_J))`, a commitment to the joiner's Noise ephemeral public key `e_J` |
| 1 | `"1"` | inviter → joiner | `base64(` Noise message 1 (`psk, e`) `)`, payload `{"t":"pair1"}` and nothing else |
| 2 | `"2"` | joiner → inviter | `base64(` Noise message 2 (`e, ee`) `)` with `e = e_J`, payload `{"t":"pair2","name":…,"relays":[…]}` (the joiner's) |
| 3 | `"3"` | inviter → joiner | `NIP-44(confirm_key, …)`, control class. Accept: `{"t":"pair3","ok":true,"name":…,"relays":[…],"epoch":e_p}` with the inviter's name and home relays and `e_p = epoch(now)`. Decline: `{"t":"pair3","ok":false}` |

Rules:

- **One event per step.** Each side MUST accept exactly one event per step: the first that passes
  the envelope checks (§12, items 1–4, with `d` equal to the step). Copies of that same event (same
  id) arriving from other relays are ignored.
  - Before the pairing has ended, a *different* envelope-valid event for a step already accepted
    MUST abort the pairing. So MUST an accepted event that fails its step's own checks (below).
  - Only someone who knows the PSK can produce an envelope-valid event, so either case means the
    invite is in other hands. The app says so, and the users start again with a new invite.
  - An event for a step that is not yet due (a step 3 before step 2 was sent, say) is held until it
    is due.
- **Joiner.** It generates `e_J` once per invite and uses it in exactly one step 2. It answers only
  the accepted step 1, and MUST send step 2 at most once: a retransmission repeats the same event. An
  implementation that persists the pairing state MUST record the accepted step 1 durably before it
  publishes step 2.
- **Inviter.** It sends step 1 only after accepting a step 0, and MUST send it at most once (a
  retransmission repeats the same event): each further step 1 would give a man in the middle another
  try at matching the codes. On step 2, it MUST first check, in constant time, that
  `SHA256(label("commit") || e)` equals the commitment from step 0.
- The joiner MUST reject `e_p` if `|e_p − epoch(now)| > 1`.
- After step 2, both sides show the code (§6.4). The inviter's app shows the joiner's name next to
  the code and asks the user to accept or decline. Step 3 carries the decision and, on acceptance,
  the inviter's name, relays and `e_p`. Nothing else is sent.
- Noise messages 1 and 2 carry a 512-byte (control-class) payload: 32 + 512 + 16 = 560 bytes each.

After step 2 both sides call Noise `Split()` and keep its raw keys:

- `k1` (initiator→responder = inviter→joiner);
- `k2` (joiner→inviter).

`confirm_key = HKDF-Expand(k1, label("pair3"), 32)`. `k1` and `k2` are the roots of the two channel
directions (§7). Both are used only through HKDF-Expand with distinct labels; the Noise transport
ciphers are not used.

**Erasure.** `k1` and `k2` MUST be erased as soon as `CK(e_p)` of both directions has been
derived: by the inviter when it sends step 3, and by the joiner when it accepts step 3. Whoever holds
a root can compute every later chain key, which would void the forward secrecy of §7. The handshake
state, the ephemeral keys and `psk` are erased when the pairing ends.

**What an intercepted invite reveals.** Someone who knows the PSK and records the relays' traffic
can decrypt step 1, which carries nothing. The joiner's name and relays travel in step 2, and the
inviter's in step 3. Both are under keys that need the `ee` exchange. The eavesdropper learns only
the relay list that the invite itself contains.

**Why the commitment and the one-event rule.** A man in the middle who knows the PSK (an
intercepted invite) runs one handshake with each side. Without step 0, it would pick its ephemeral
key towards the joiner *after* seeing everything on the inviter's side. It could then try keys
offline until the two short codes match (~10⁶ tries). With step 0 and one event per step:

- its key towards the inviter is committed before it sees the inviter's key;
- the joiner's key is committed before the man in the middle must choose its key towards the
  joiner;
- the joiner reveals its key in exactly one step 2, as the answer to exactly one step 1. If it
  answered a second step 1 with the same key, the man in the middle could take that key from the
  first step 2 and grind its own step 1 offline. That is about 10⁶ X25519 operations, a minute or
  two on one core.

Each code is then random to the man in the middle, and a match succeeds with probability 10⁻⁶. It
gets one attempt per invite. Short-code verification schemes use the same structure: Matrix SAS
verification, ZRTP's hash commitment, Bluetooth numeric comparison.

### 6.4 Short authentication string

```
sas = u32be(HKDF-Expand(k1, "nll1:sas", 4)) mod 1000000     shown as "ddd ddd"
```

`k1` is the first `Split()` output. It depends only on the PSK, the two ephemeral public keys and
their Diffie-Hellman result. Noise mixes payloads into the handshake hash `h`, never into the chaining
key that `Split()` expands. Equal codes on both screens show that both sides hold the same keys, and
that no one sits in the middle (design doc, threat T6).

The code MUST NOT be derived from `h`. An earlier draft did, and a man in the middle could then vary
the step 2 payload it sends to the inviter until the inviter's code matched the joiner's. Receivers
ignore unknown JSON members, so any byte would do, and it needs no new keys. Payload integrity does
not depend on the code. Noise authenticates every payload with `h` as associated data, so a changed
step 1 makes step 2 fail at the inviter, and steps 2 and 3 are encrypted under `ee`-derived keys.

In-person pairing by QR gets the comparison for free: the inviter sees the code next to the joiner's
name. For remote pairing, the users can compare codes by voice.

## 7. Channels

Each direction of a pair (A→B and B→A) is an independent chain:

```
CK(e_p)   = HKDF-Expand(root, label("ck") || u32be(e_p), 32)        root = k1 or k2 from §6.3
CK(e + 1) = HKDF-Expand(CK(e), label("ck-next"), 32)
ctl_sk(e) = derive_secp_key(CK(e), "ctl-sign")      channel event key; ctl_pk(e) its x-only key
ctl_ck(e) = HKDF-Expand(CK(e), label("ctl-enc"), 32)   NIP-44 conversation key
```

- Both ends of a pair hold both directions' chains: the sender to write, the receiver to read.
- **Ratchet.** `CK(e)` MUST be erased, in both directions and at both ends, once
  `now ≥ epoch_end(e) + 3600`. A device stores, per direction, only the chain key of the oldest epoch
  it still needs, `epoch(now − 3600)` (or a later one). It derives later epochs on demand without
  storing them. Earlier epochs are then unrecoverable, which gives forward secrecy with one-day
  granularity. The roots `k1` and `k2` are erased at pairing (§6.3).
- Implementations ratchet when they start and on a timer while running. A device that does not run
  for days keeps an older chain key, and if seized it yields the keys from that day on. Implementations
  SHOULD therefore also ratchet once a day while idle. That is a local computation that sends nothing
  (design doc, decision D16).
- Receivers accept channel events signed by `ctl_pk` of `epoch(now) − 1` (until its key is erased),
  `epoch(now)` and `epoch(now) + 1` (clock skew around midnight UTC).

## 8. Channel state (control messages)

Each direction has a single addressable slot (kind `30484`, `d = ""`, pubkey `ctl_pk(e)` for
`e = epoch(created_at)`). The slot holds the sender's **current state towards that contact**:

```json
{"t":"state","seq":7,"ts":1760000200,
 "relays":["wss://nos.lol","wss://nostr.mom","wss://relay.primal.net"],
 "share":{"until":1760003800,"pk":"<stream pubkey, 64 hex>","key":"<stream key, base64 of 32 bytes>"}}
```

- `seq` is a per-direction counter, starting at 1 and strictly increasing across epochs.
  Receivers MUST ignore a state whose `seq` is not greater than the last one accepted from that
  contact. This stops a relay replaying an old grant after the share ended.
- `relays` are the sender's current home relays.
- `share` is present while the sender shares with this recipient. `until` is when this
  recipient's access ends (0 = until stopped). A state without `share` ends any earlier grant.
- Encryption: `content = NIP-44(ctl_ck(e), plaintext)`, control class.
- `expiration = epoch_end(e) + 3600`.
- Published to the **recipient's** home relays (its inbox, §11).
- A sender with an active share republishes its state under the new epoch's key at the first
  opportunity after midnight UTC (the stream also rotates then, §9).

## 9. Location stream

A stream is `(stream_sk, stream_key)`: a fresh valid secp256k1 secret and 32 random bytes, both from
the CSPRNG. Only the sharer knows `stream_sk`; current recipients get `stream_pk` and `stream_key` in
their grants.

**Rotation.** The sharer MUST start a new stream whenever:

- a recipient is added, so newcomers cannot decrypt anything published before they were granted;
- a recipient is removed, or its `until` passes;
- a new epoch starts.

A new `until` for a current recipient needs no new stream, only a new state for that recipient.

**Order of a change.** At the moment of the change, T0, the sharer publishes in this order:

1. the states: a grant of the new stream to every remaining recipient and a state without `share`
   to every removed one, in random order;
2. the `end` of the old stream.

It then erases the old `stream_sk` and `stream_key`. The new stream MUST NOT publish its first event
before `T0 + δ`, with δ drawn uniformly from 30–120 s by the CSPRNG.

Stopping the share altogether publishes the same: a state without `share` to every recipient, in
random order, then the `end`. A removed recipient therefore sees exactly what it would see if the
sharer had stopped: its own state without `share`, among the same number of states, and the same
`end`. The remaining recipients get their grants before the `end`, so they move to the new stream
without a gap in what they show.

A sharer that has lost `stream_sk` (its process died) cannot publish the `end`. The old stream's
last event then simply expires. Recipients treat a new grant, or a state without `share`, as the end
of the stream they had. What a removed recipient can still attempt is traffic analysis: a new
stream may appear on the sharer's relays 30–120 s later (design doc, threat T4).

**Events.** Kind `30484`, pubkey `stream_pk`, tags `[["d",""],["expiration",x]]`,
`content = NIP-44(stream_key, plaintext)` (stream class), published to the **sharer's** home relays.

- `loc`: `{"t":"loc","seq":1,"ts":1760000205000,"lat":52.5200066,"lon":13.404954,"acc":8.0,"spd":1.4,"brg":271.0}`
  - `seq` is strictly increasing per stream, from 1.
  - `ts` is the fix time in milliseconds.
  - `lat`/`lon` are WGS-84 degrees with at most 7 decimals; `acc` is the horizontal accuracy in metres.
  - Optional: `spd` (m/s), `brg` (degrees), `alt` (m), `low` (`true` when the sharer's battery is
    low), and `nav` (`{"eta":<unix>,"dist":<metres>,"dest":<≤48 bytes>}`, reserved for trip sharing).
  - `x = created_at + 900`, never capped by recipients' `until`. A cap at the largest `until`, as an
    earlier draft had it, told every recipient whether someone else's access lasted longer than its
    own. The `end` published at each `until` replaces the last position anyway.
- `end`: `{"t":"end","seq":n,"ts":<unix>}`, with `x = created_at + 900`. Every `end` is identical
  in form whatever its cause: stop, removal, time limit, new epoch, low battery. It carries no
  reason.

Because the slot is addressable, relays that follow NIP-01 and NIP-40 keep **only the latest** event
of a stream, and drop it 15 minutes after it was published (sooner when the stream ends). Nothing
stops a relay or any other client from keeping copies of the ciphertext. Their confidentiality
afterwards rests on the erasure rules (§13).

## 10. Signals (viewer → sharer)

While a viewer has the map open and is showing a contact's active share, it MAY publish a `watch`
signal at most every 60 seconds:

- kind `20484`, signed with the viewer's `ctl_sk(e)` towards that contact, no tags;
- `content = NIP-44(ctl_ck(e), {"t":"watch","ts":<unix>,"until":<unix>})` (stream class);
- published to **all** of the sharer's home relays, so that a sharer may listen on only one of them
  (design doc §10.3).

The sharer treats itself as "watched" until `min(until, now + 120)`. Signals older than 60 s are
ignored. What the sharer does with this (faster updates) is policy, see the design doc (decision D4).

## 11. Relays

Every user has 1–4 **home relays**, user-configurable, defaulting to the list in the design doc.

| Message | Published to | Read from |
|---|---|---|
| pairing steps 0–3 | inviter's home relays (from the invite) | same |
| state A→B | B's home relays (B's inbox) | B reads its own home relays |
| stream | A's home relays | recipients read A's home relays (from A's `state.relays`) |
| watch signal B→A | A's home relays | A reads its own home relays |

Subscriptions (NIP-01 `REQ`, at most 50 authors per filter; longer lists are split into several
filters of the same `REQ`):

- **Inbox**, on one's own home relays: one `REQ` with two filters over the same author list `I(e)`:
  `{"kinds":[30484],"authors":I(e)}` and `{"kinds":[20484],"authors":I(e),"since":now−60}`.
  - `I(e)` holds `ctl_pk(e)` of every contact's channel towards me, for a single epoch `e`.
  - It is padded with decoys (below) to the next multiple of 8 and sorted.
  - One list serves states and signals, so a relay cannot tell which contacts share with me or
    receive my share. The padding hides the exact number of contacts.
- **Streams**, on each sharing contact's home relays: `{"kinds":[30484],"authors":[stream_pk]}`
  with the stream key of that contact's current grant.
- **Pairing**, while an invite is pending: `{"kinds":[30484],"authors":[rv_pk]}` on the inviter's
  relays.

**Decoys.**

```
decoy_sk(e, i) = derive_secp_key(HKDF-Expand(decoy_seed, label("decoy") || u32be(e) || u32be(i), 32), "decoy-sign")
```

- `i = 0, 1, …`, and `decoy_pk(e, i)` is its x-only key. With `n` contacts, `I(e)` takes the decoys
  `i < 8·⌈n/8⌉ − n`.
- `decoy_seed` is 32 bytes from the CSPRNG, made once per device and never sent.
- The decoys are stable for the whole epoch, so reconnecting does not reveal which keys are real.
  Over a day, a relay still learns that the keys that received events are real.

**One epoch per connection.** A connection MUST NOT carry keys of two epochs. That covers its
subscriptions and the events published over it. A stream counts as belonging to the epoch in which
it was created. At midnight UTC, clients close their connections and open new ones for the new epoch.
Events still signed under the previous epoch, until they expire, are read over a separate
connection. Otherwise the relay could link one day's pseudonyms to the next day's through the
connection, whatever the IP address. Within one day, keys used over the same connection are
linkable.

Publishers send each event to all relevant relays and treat it as delivered when at least one relay
answers `OK true`. Receivers deduplicate by event id.

## 12. Receiving rules

Every event must pass all of these checks; cheap ones may run first, but the signature MUST be verified
before anything is decrypted (as NIP-44 requires):

1. the event id equals SHA256 of its serialization, and the BIP-340 signature is valid;
2. kind and pubkey are among those expected for the subscription, and the `d` tag is as expected;
3. for kind `30484`: `expiration` is present, is an integer and is `> now`;
4. `created_at ≤ now + 300`; signals additionally `created_at ≥ now − 60`;
5. NIP-44 decryption with the context's key succeeds (MAC, padding), and the plaintext is a JSON
   object with a string `"t"`;
6. the type-specific checks hold: `seq` ordering (§8, §9), field ranges, relay-list limits.

Any failure discards the event silently, except during pairing, where §6.3 says when to abort.

A recipient keeps a stream key only while its grant is current. It MUST erase the key when a new
grant replaces it, when the stream's `end` arrives, and when the grant's `until` passes. It also
enforces `until` locally, whatever the sharer does. Positions are kept in memory only (design doc
§8.5).

## 13. Obligations (summary)

Anyone can archive ciphertext from public relays. Past positions stay confidential only if every key
that could decrypt them is erased, at both ends:

| Secret | Erased by | When |
|---|---|---|
| `psk`, Noise ephemeral keys and handshake state | both pairing sides | when the pairing ends or the invite expires (§6.3) |
| roots `k1`, `k2` | both pairing sides | once `CK(e_p)` is derived (§6.3) |
| `CK(e)` | both ends, both directions | at `epoch_end(e) + 3600` (§7) |
| `stream_sk`, `stream_key` | the sharer | when the stream is replaced or ends (§9) |
| `stream_key` | each recipient | when its grant is replaced, at the stream's `end`, when `until` passes (§12) |

Erasure has to reach storage, not only memory. Overwriting or renaming a file does not erase its
old blocks on flash, so implementations encrypt stored state with a key that is replaced, and the
old one destroyed, whenever the state above is erased (design doc §10.4).

Further obligations:

- Pairing: one event per step, and abort on a second (§6.3).
- Rotate the stream on every membership change and every epoch, in the order of §9.
- One epoch per connection, decoys in the inbox subscription (§11).
- Never publish anything for a contact the user has not explicitly shared with. After the user
  stops sharing, publish nothing but the final states and the `end`.
- Strictly increasing `created_at` per event pubkey (§4).

## 14. Constants

| Constant | Value |
|---|---|
| kinds | `30484` (addressable), `20484` (ephemeral) |
| epoch length | 86400 s (UTC days) |
| plaintext classes | 512 (control), 256 (stream) bytes |
| location and stream-end expiry | 900 s after `created_at` |
| channel state expiry | `epoch_end(e) + 3600` |
| channel key retention | until `epoch_end(e) + 3600` |
| future skew accepted | 300 s |
| signal: max age, max lease | 60 s, 120 s |
| silence of a replacement stream | uniform 30–120 s |
| relay lists | 1–4 `wss://` URLs of ≤ 64 bytes (`ws://` only to loopback) |
| authors per REQ filter | ≤ 50 |
| inbox subscription | padded with decoys to a multiple of 8 |

## 15. Test vectors

`vectors/nll1_vectors.json` lists, for one complete scenario, every input and every intermediate value:

- invite bytes, link, rendezvous key and Noise prologue;
- all four pairing steps (commitment, both Noise messages, confirmation with the inviter's name,
  relays and pairing epoch), the handshake hash (for debugging only), the split keys and the SAS;
- channel keys for three epochs in both directions;
- a state with a grant and a state without one;
- a location, a stream end and a watch signal;
- an inbox subscription with its decoys.

Random inputs are given per step in the order they are consumed (`random`: NIP-44 nonce first, then the
BIP-340 auxiliary randomness), so an implementation can reproduce each event byte for byte. Each event
also carries its canonical `serialized` form.

The primitives are checked separately against the published NIP-44 v2, BIP-340, RFC 5869 and Noise
(cacophony) vectors by `test_primitives.py`.
