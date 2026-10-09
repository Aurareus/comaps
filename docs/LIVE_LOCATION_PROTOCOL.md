# NLL v1: private live location over Nostr (protocol specification)

Status: **draft for review** (Phase 1). Nothing here is final until the decisions in
[LIVE_LOCATION.md](LIVE_LOCATION.md#14-decisions-to-sign-off) are signed off.

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

There are no long-term identity keys. Nothing a relay sees (event keys, tags, content, sizes) is derived
from or linkable to a person, a device or a contact relationship, except through network metadata
(IP addresses and timing), see the threat model.

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

Common field limits: relay lists contain 1–4 URLs, each `wss://` or `ws://` and at most 64 bytes;
names are at most 64 bytes.

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
invite, 141-character link. Each invite is **single-use**: the inviter processes at most one
commitment (§6.3) and forgets `psk` after the handshake ends or the invite expires.

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
| 0 | `"0"` | joiner → inviter | `base64(SHA256(label("commit") \|\| e_J))`, a commitment to the joiner's Noise ephemeral public key `e_J`, chosen now |
| 1 | `"1"` | inviter → joiner | `base64(` Noise message 1 (`psk, e`) `)`, payload `{"t":"pair1","name":…,"relays":[…],"epoch":e_p}` with `e_p = epoch(now)` |
| 2 | `"2"` | joiner → inviter | `base64(` Noise message 2 (`e, ee`) `)` with `e = e_J`, payload `{"t":"pair2","name":…,"relays":[…]}` |
| 3 | `"3"` | inviter → joiner | `NIP-44(confirm_key, {"t":"pair3","ok":true\|false})`, control class |

Rules:

- The inviter MUST process at most one step 0 per invite (single use), and send step 1 only after
  it.
- On step 2, the inviter MUST check that `SHA256(label("commit") || e)` equals the commitment from
  step 0 (constant-time) before anything else, and abort otherwise.
- The joiner MUST reject `e_p` if `|e_p − epoch(now)| > 1`.
- After step 2 both sides know the final handshake hash `h` and show the code (§6.4). The inviter's
  app shows the joiner's name and the code and asks the user to accept or decline. Step 3 carries the
  decision. Nothing else is sent.
- Noise messages 1 and 2 carry a 512-byte (control-class) payload: 32 + 512 + 16 = 560 bytes each.

After step 2 both sides call Noise `Split()` and keep its raw keys:

- `k1` (initiator→responder = inviter→joiner);
- `k2` (joiner→inviter).

`confirm_key = HKDF-Expand(k1, label("pair3"), 32)`. `k1` and `k2` are the roots of the two channel
directions (§7). Both are used only through HKDF-Expand with distinct labels; the Noise transport
ciphers are not used. The handshake state, the ephemeral keys and `psk` are erased after step 3.

**Why the commitment.** A man in the middle who knows the PSK (an intercepted invite) runs one
handshake with each side. Without step 0, it would pick its ephemeral key towards the joiner *after*
seeing everything on the inviter's side, and could try keys offline until the two short codes match
(~10⁶ tries). With step 0:

- its key towards the inviter is committed before it sees the inviter's key;
- the joiner's key is committed before the man in the middle must choose its key towards the joiner.

Each code is then random to it, and a match succeeds with probability 10⁻⁶ per attempt. Short-code
verification schemes work the same way: Matrix SAS verification, ZRTP's hash commitment, Bluetooth
numeric comparison.

### 6.4 Short authentication string

```
sas = u32be(HKDF-Expand(h, "nll1:sas", 4)) mod 1000000     shown as "ddd ddd"
```

`h` is the final Noise handshake hash. Equal codes on both screens show that both sides completed
the same handshake (design doc, threat T6). In-person pairing by QR gets this for free (the inviter
sees the code next to the joiner's name); for remote pairing the users can compare codes by voice.

## 7. Channels

Each direction of a pair (A→B and B→A) is an independent chain:

```
CK(e_p)   = HKDF-Expand(root, label("ck") || u32be(e_p), 32)        root = k1 or k2 from §6.3
CK(e + 1) = HKDF-Expand(CK(e), label("ck-next"), 32)
ctl_sk(e) = derive_secp_key(CK(e), "ctl-sign")      channel event key; ctl_pk(e) its x-only key
ctl_ck(e) = HKDF-Expand(CK(e), label("ctl-enc"), 32)   NIP-44 conversation key
```

- Both ends of a pair hold both directions' chains: the sender to write, the receiver to read.
- `CK(e)` MUST be erased once `now ≥ epoch_end(e) + 3600`. Keys for later epochs are derived on
  demand; earlier ones are unrecoverable, which gives forward secrecy with one-day granularity.
- Receivers accept channel events signed by `ctl_pk` of `epoch(now) − 1`, `epoch(now)` and
  `epoch(now) + 1` (clock skew around midnight UTC).

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

**Rotation.** The sharer MUST start a new stream, and publish new states to the recipients who
remain, whenever:

- a recipient is added, so newcomers cannot decrypt anything published before they were granted;
- a recipient is removed, or its `until` passes;
- a new epoch starts.

The old stream receives an `end` with `"why":"rotated"`. Removed recipients receive a state without
`share`.

**Events.** Kind `30484`, pubkey `stream_pk`, tags `[["d",""],["expiration",x]]`,
`content = NIP-44(stream_key, plaintext)` (stream class), published to the **sharer's** home relays.

- `loc`: `{"t":"loc","seq":1,"ts":1760000205000,"lat":52.5200066,"lon":13.404954,"acc":8.0,"spd":1.4,"brg":271.0}`
  - `seq` is strictly increasing per stream, from 1.
  - `ts` is the fix time in milliseconds.
  - `lat`/`lon` are WGS-84 degrees with at most 7 decimals; `acc` is the horizontal accuracy in metres.
  - Optional: `spd` (m/s), `brg` (degrees), `alt` (m), `low` (`true` when the sharer's battery is
    low), and `nav` (`{"eta":<unix>,"dist":<metres>,"dest":<≤48 bytes>}`, reserved for trip sharing).
  - `x = created_at + 900`. When every current recipient has `until ≠ 0`, `x` is capped at the
    largest `until`.
- `end`: `{"t":"end","seq":n,"ts":<unix>,"why":"stopped"|"rotated"|"expired"|"battery"}`,
  with `x = created_at + 900`.

Because the slot is addressable, relays keep **only the latest** event of a stream, and it disappears
15 minutes after it was published (sooner when a share ends).

## 10. Signals (viewer → sharer)

While a viewer has the map open and is showing a contact's active share, it MAY publish a `watch`
signal at most every 60 seconds:

- kind `20484`, signed with the viewer's `ctl_sk(e)` towards that contact, no tags;
- `content = NIP-44(ctl_ck(e), {"t":"watch","ts":<unix>,"until":<unix>})` (stream class);
- published to the sharer's home relays.

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

Subscriptions (NIP-01 `REQ`; at most 50 authors per filter, split otherwise):

- on one's own home relays: `{"kinds":[30484],"authors":[ctl_pk(e−1..e+1) of every contact's channel towards me]}`;
- on each sharing contact's home relays: `{"kinds":[30484],"authors":[stream_pk of their current grant]}`;
- while sharing, on one's own home relays: `{"kinds":[20484],"authors":[ctl_pk(e) of each recipient's channel towards me],"since":now}`;
- while an invite is pending: `{"kinds":[30484],"authors":[rv_pk]}` on the inviter's relays.

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

Any failure discards the event silently.

## 13. Sender obligations (summary)

- Erase channel keys on schedule (§7), stream secrets on rotation, and the PSK and Noise state after
  pairing.
- Rotate the stream on every membership change and every epoch (§9).
- Never publish anything for a contact the user has not explicitly shared with. Never publish after
  the user stops sharing, except the final `end` events and states.
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
| relay lists | 1–4 URLs of ≤ 64 bytes |
| authors per REQ filter | ≤ 50 |

## 15. Test vectors

`vectors/nll1_vectors.json` lists, for one complete scenario, every input and every intermediate value:

- invite bytes, link, rendezvous key and Noise prologue;
- all four pairing steps (commitment, both Noise messages, confirmation), the handshake hash, the
  split keys and the SAS;
- channel keys for three epochs in both directions;
- a state with a grant and a state without one;
- a location, a stream end and a watch signal.

Random inputs are given per step in the order they are consumed (`random`: NIP-44 nonce first, then the
BIP-340 auxiliary randomness), so an implementation can reproduce each event byte for byte. Each event
also carries its canonical `serialized` form.

The primitives are checked separately against the published NIP-44 v2, BIP-340, RFC 5869 and Noise
(cacophony) vectors by `test_primitives.py`.
