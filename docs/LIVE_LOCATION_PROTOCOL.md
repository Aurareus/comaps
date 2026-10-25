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
- Decoders are strict, so that implementations agree on every input. They accept only the alphabet,
  padding exactly as the encoder writes it (none for base64url), and canonical input: re-encoding
  the result gives back the input, so unused trailing bits are zero. Hex must be lowercase.

## 3. Primitives

| Name | Definition |
|---|---|
| `SHA256`, `HMAC-SHA256` | FIPS 180-4, RFC 2104 |
| `HKDF-Extract(salt, ikm)`, `HKDF-Expand(prk, info, L)` | RFC 5869 with SHA-256 |
| BIP-340 | Schnorr signatures over secp256k1, x-only public keys (as required by NIP-01) |
| NIP-44 v2 | [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) from step 2 onward ("generate nonce" … "base64"), with the conversation key given by this spec instead of ECDH. Plaintexts are limited to 65535 bytes (this profile never uses the extended length prefix). |
| Noise | `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, Noise Protocol Framework revision 34. One addition: if the `ee` Diffie-Hellman result is all zeros (the peer sent a low-order public key), the handshake MUST abort. RFC 7748 §6.1 allows this check and Noise leaves it optional; implementations differ (PyCA refuses such keys, Monocypher returns zeros), and an unchecked zero would leave the handshake keyed by the PSK alone. |
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

- Kind `30484` events MUST carry exactly these tags, in this order: `["d", <value>]`; for the
  joiner's pairing steps only, `["p", <ipk>]` (§6.3); and `["expiration", <decimal>]` (NIP-40). The
  `d` value is `""` except for pairing messages (§6).
- Kind `20484` events carry no tags.
- A sender MUST make `created_at` strictly increase per event pubkey: relays keep only the addressable
  event with the highest `created_at` (lowest id on ties), so two updates in the same second could
  otherwise lose the newer one. Senders use `max(now, previous_created_at + 1)`.
- No other tags are used. The one `p` tag points at the inviter's one-time pairing key, never at
  anything derived from a user's identity.

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

**JSON profile.** Plaintexts are I-JSON (RFC 7493):

- valid UTF-8;
- no duplicate member names;
- no unpaired surrogates, including in `\u` escapes;
- only finite numbers: `NaN` and `Infinity` are not JSON, and a number that overflows a double is
  rejected rather than turned into infinity.

An **integer** is a JSON number without a fraction or exponent part, between −(2⁵³ − 1) and
2⁵³ − 1. `5.0` and `true` are not integers. Receivers MUST reject plaintexts that break any of
this (§12). Common parsers differ on exactly these points: Python's `json` accepts `NaN`, `Infinity`
and duplicate names, and jansson rejects them. Two implementations agree only if both apply this
profile.

Consequence: all NIP-44 payloads of one class have the same length (432 base64 characters for the
stream class, 772 for the control class) whatever their contents.

Common field limits:

- Relay lists contain 1–4 URLs of at most 64 bytes each.
- Every URL is `wss://` followed by one or more printable ASCII characters (0x21–0x7E) other than
  `"` and `\`. The only exception is `ws://` to a loopback host, for local test relays: `ws://`
  then `localhost`, `127.0.0.1` or `[::1]`, an optional `:` with 1–5 digits, and an optional path of
  those characters starting with `/`. Senders MUST NOT send, and receivers MUST reject, any other
  URL: without TLS, an on-path observer would see the event keys and contents that TLS hides
  (design doc, threat T3). The rule is stated as a pattern rather than by reference to a URL
  parser, because parsers differ.
- Names are 1–64 bytes without control characters (U+0000–U+001F, U+007F).
- JSON writes `"` and `\` as two bytes and control characters as six, which no URL or name may
  hold for that reason: the largest messages a sender can then make fit their size. With four
  URLs of 64 bytes, a sequence number at the largest JSON integer and times of ten digits, a state
  with a grant and the colour `deeppurple` is 506 bytes, a `pair3` with a name of 64 quotes 465,
  and a location with six numbers of 24 characters 253 (of 256).

## 6. Pairing

### 6.1 Invite

```
invite = u8(1)                      version
      || psk[32]                    from the CSPRNG
      || ipk[32]                    the inviter's pairing public key (x-only, §6.2)
      || u32be(expires_at)          invite lifetime end
      || u8(n)                      1 ≤ n ≤ 4
      || n × (u8(len) || url[len])  the inviter's home relays (§11)
link   = "comaps://live/pair#" || base64url(invite)
```

The invite is shown as a QR code of `link` or sent as `link` over any channel. With the three
default relays it is 122 bytes, a 182-character link, QR version 10 at error correction M (the
vectors' example, whose third relay is longer, is 123 bytes and 183 characters). Receivers
reject an invite with trailing bytes, an `ipk` that is not a valid x-only key, or relays that break
§5. Each invite is **single-use** (§6.3).

QR invites live 10 minutes and link invites 24 hours. An invite MUST NOT live longer than 24 hours,
and a joiner MUST refuse one whose `expires_at` is more than 86400 + 300 s ahead of its clock. The
inviter chooses the relays that the joiner watches until `expires_at` (§6.3). Without the cap, an
inviter running one of them could keep a joiner's phone connecting to it, and so learn its IP
address, for years. A joiner also applies relay consent (§11) to the invite's relays before
connecting to them.

Every pairing event stays on the relays until the invite expires, so the two apps need not be open at
the same moment. Each step is taken when the
app that owes it is next open. Implementations therefore keep the pairing state (encrypted, design
doc §8.5) until the pairing ends or the invite expires.

### 6.2 Pairing keys

Each side signs its own pairing events:

- `isk`, `ipk`: the **inviter's pairing key**, a fresh secp256k1 key from the CSPRNG for each
  invite. `ipk` is in the invite. It signs steps 1 and 3.
- `jsk`, `jpk`: the **joiner's pairing key**, fresh for each attempt to join. It signs steps 0 and 2.
- `mac_key = HKDF-Expand(HKDF-Extract(salt = "nll1:pair", ikm = psk), label("pair-mac"), 32)`.
  In step 0 it proves that the step's author holds the invite.

Someone who holds the link knows `ipk` but not `isk`, so it can neither sign, replace nor delete the
inviter's pairing events. Likewise, nobody can replace or delete a joiner's events, since addressable
replacement and NIP-09 deletion both require the same key.

An earlier draft signed all four steps with one key derived from the PSK. Anyone holding the link
could then replace a step on the relays, since an addressable slot keeps only the newest event per
key and `d`. It could also delete a step with a NIP-09 deletion request, which relays honour for
events of the same key. A party that was offline at that moment saw only the impostor's event.
Moving to a regular (never replaced) kind would not have stopped the deletion.

### 6.3 Handshake

The **inviter** (who showed the invite) is the Noise **initiator**; the **joiner** (who scanned or
opened it) is the **responder**.

```
c        = SHA256(label("commit") || e_J)          the joiner's commitment to its ephemeral public key
prologue = label("pair") || u8(1) || ipk || u32be(expires_at) || u8(n) || relays… || jpk || c
```

The prologue is the invite without the PSK (Noise mixes the PSK in itself), followed by the author
and the commitment of the step 0 being answered.

All four messages are kind `30484` events with `expiration = expires_at`, published to the invite's
relays:

| Step | Author | Tags | Content |
|---|---|---|---|
| 0 | joiner, `jsk` | `["d","0"]`, `["p",ipk]` | `base64(c \|\| HMAC-SHA256(mac_key, jpk \|\| c))` |
| 1 | inviter, `isk` | `["d","1"]` | `base64(` Noise message 1 (`psk, e`) `)`, payload `{"t":"pair1"}` and nothing else |
| 2 | joiner, `jsk` | `["d","2"]`, `["p",ipk]` | `base64(` Noise message 2 (`e, ee`) `)` with `e = e_J`, payload `{"t":"pair2","name":…,"relays":[…]}` (the joiner's) |
| 3 | inviter, `isk` | `["d","3"]` | `NIP-44(confirm_key, …)`, control class. Accept: `{"t":"pair3","ok":true,"name":…,"relays":[…],"epoch":e_p}` with the inviter's name and home relays. Decline: `{"t":"pair3","ok":false}` |

Subscriptions on the invite's relays, kept until the invite expires:

- the inviter: `{"kinds":[30484],"#p":[ipk]}`;
- the joiner: `{"kinds":[30484],"authors":[ipk]}` and `{"kinds":[30484],"#p":[ipk]}`.

A step that no relay has accepted yet is published again, as the same event, until one does or the
invite expires; a client keeps it across a restart for that. Publishing it again is not a second step:
it has the same id, and relays keep one event per step and author.

**Definitions.**

- An event is **envelope-valid for step s** when it passes §12 items 1–4 with `d` equal to `s`.
  For steps 1 and 3 its author must be `ipk`. For steps 0 and 2, its first `p` tag must be `ipk`.
- A **valid step 0** is an envelope-valid step 0 whose content decodes to 64 bytes `c || tag`, with
  `tag = HMAC-SHA256(mac_key, author || c)` compared in constant time. Only a holder of the invite
  can make one.
- Envelope-valid events that are not valid step 0s carry no weight. They are ignored, never a
  reason to abort, so nobody who merely sees `ipk` on a relay can disrupt a pairing.

**Inviter.**

1. It accepts the first valid step 0. That event's author `jpk` and commitment `c` are the
   joiner's.
2. It sends exactly one step 1, with the prologue bound to `(jpk, c)`. A retransmission repeats the
   same event.
3. It accepts a step 2 only from `jpk`. The first one MUST open the commitment, checked in constant
   time (`SHA256(label("commit") || e) = c`), and decrypt; otherwise the pairing aborts.
4. It shows the joiner's name and the code (§6.4), and the user decides. Step 3 carries the
   decision. On acceptance it also carries the inviter's name, relays and
   `e_p = epoch(now − 300)`. The lag of 300 s, the accepted clock skew (§12), keeps `e_p` from ever
   being in the joiner's future. The inviter MUST NOT send step 3 once the invite has expired:
   relays would refuse it, and the joiner has stopped listening.
5. Its new contact is **unconfirmed** until a state or a watch signal arrives on the contact's
   channel towards it (the joiner's confirmation, below). The joiner may never get step 3: it may
   come back after the invite expired, refuse the code, or abort on a late conflict. Unconfirmed is
   a label, not a block: the user may share with the contact. If the joiner never finished, nothing
   leaks, since nobody else holds the channel keys. The app offers to remove the contact only if it
   is still unconfirmed at `epoch_end(e_p + 7) + 3600`, when the last confirmation the joiner owed
   has expired.

**Joiner.**

1. It makes `e_J` and `jsk` once per invite and publishes exactly one step 0.
2. It accepts the first step 1 signed by `ipk`. That step MUST decrypt under the prologue bound to
   the joiner's own `(jpk, c)`. If it does not, the inviter answered someone else, and the joiner
   aborts without sending step 2.
3. It sends exactly one step 2. A retransmission repeats the same event. An implementation that
   persists the pairing state MUST record step 0 and the accepted step 1 durably before publishing
   what follows.
4. It accepts the first step 3 signed by `ipk`. That step MUST decrypt under `confirm_key` and, on
   acceptance, carry `e_p` with `epoch(now) − 1 ≤ e_p ≤ epoch(now)`. Otherwise the pairing aborts.
5. Right after accepting step 3, it MUST publish a state without `share` on the new channel, to the
   inviter's relays from step 3 (§8, under relay consent, §11). This is the **confirmation**:
   completion is two-sided only when the inviter has received it. A state can be read only until an
   hour after the end of its UTC day, and the inviter might not run in that time. So through epoch
   `e_p + 7`, whenever the joiner runs on a UTC day on which it has published no state on this
   channel, it MUST publish its **current** state there: with its grant while it shares with the
   inviter, since a state without `share` would end that share.

The confirmation uses the channel's daily keys, like any state. A key that outlived the day would
make the inviter query that same key every day, which links its daily connections: exactly what the
one-epoch-per-connection rule prevents (§11). A longer expiry would not help either: the inviter
erases each day's channel key an hour after the day ends (§7).

**Conflicts.** Both sides watch their subscriptions until the invite expires, whenever they are
online. The joiner's `#p` subscription also returns its own events, which it ignores: nobody else
can sign them. A conflict is any of:

- a valid step 0 other than the accepted one (inviter) or the joiner's own (joiner);
- a second, different event for a step already accepted.

Either means that someone else holds the invite. Before the pairing has ended, both sides MUST abort
on a conflict, erase everything and tell the user. After it has ended (the inviter has decided, or
the joiner has accepted step 3), they keep the contact but MUST flag it and warn the user (design doc
§11.2). Whether a flagged contact may still receive shares is decision D18 of the design doc. Nobody
can remove another party's events, so a competing attempt stays visible to both sides until the
invite expires.

After step 2 both sides call Noise `Split()` and keep its raw keys:

- `k1` (initiator→responder = inviter→joiner);
- `k2` (joiner→inviter).

`confirm_key = HKDF-Expand(k1, label("pair3"), 32)`. `k1` and `k2` are the roots of the two channel
directions (§7). Both are used only through HKDF-Expand with distinct labels; the Noise transport
ciphers are not used.

**Erasure.** When the pairing ends or aborts, both sides MUST erase the following:

- `psk`;
- their pairing secret (`isk` or `jsk`);
- the Noise ephemeral key and handshake state;
- the roots `k1` and `k2`, as soon as `CK(e_p)` of both directions has been derived. Whoever holds a
  root can compute every later chain key, which would void the forward secrecy of §7.

Until the invite expires they keep only what watching needs: `mac_key`, `ipk`, `expires_at`, the
relays, and the ids and authors of the events they accepted. At expiry those go too.

**What someone holding the invite can do.**

| With the link… | it can | it cannot |
|---|---|---|
| read it | decrypt step 1, which carries nothing, and learn the invite's relays | read the names or relays, which travel under `ee`-derived keys |
| race the joiner | pair as an impostor if it gets there first. Its attempt is a valid step 0 under its own key, visible to both sides until expiry. If the real joiner shows up in that time, both apps abort, or flag the contact if the inviter has already decided | impersonate the inviter: steps 1 and 3 need `isk` |
| rewrite it in transit (its own invite and `ipk`) | sit in the middle of both pairings; the protocol cannot see this | make the two codes match, except with probability 10⁻⁶ |

The last two rows are why the codes matter (§6.4): a contact paired by link stays **unverified**
until its user confirms that both screens showed the same code.

**Why the commitment and the one-event rule.** A man in the middle runs one handshake with each side.
Without step 0, it would pick its ephemeral key towards the joiner *after* seeing everything on the
inviter's side. It could then try keys offline until the two short codes match (~10⁶ tries). With
step 0 and one event per step:

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

Each app marks a contact **verified** only when its own user confirms that both screens showed the
same code. In person, comparing is natural: the inviter sees the code next to the joiner's name and
the joiner's screen. For remote pairing, the users compare codes by voice; until they do, the contact
stays unverified (design doc §11.2).

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
  SHOULD therefore also ratchet about once a day while idle. That is a local computation that sends
  nothing (design doc, decision D16). "About": mobile platforms defer background jobs of rarely used
  apps, so the interval can stretch.
- Receivers accept channel events signed by `ctl_pk` of `epoch(now) − 1` (until its key is erased),
  `epoch(now)` and `epoch(now) + 1` (clock skew around midnight UTC).

## 8. Channel state (control messages)

Each direction has a single addressable slot (kind `30484`, `d = ""`, pubkey `ctl_pk(e)` for
`e = epoch(created_at)`). The slot holds the sender's **current state towards that contact**:

```json
{"t":"state","seq":7,"ts":1760000200,
 "relays":["wss://nos.lol","wss://nostr.mom","wss://relay.primal.net"],
 "share":{"until":1760003800,"pk":"<stream pubkey, 64 hex>","key":"<stream key, base64 of 32 bytes>"},
 "color":"teal"}
```

- `seq` is a per-direction counter, starting at 1 and strictly increasing across epochs.
  Receivers MUST ignore a state whose `seq` is not greater than the last one accepted from that
  contact. This stops a relay replaying an old grant after the share ended. One exception: after a
  restart, a receiver reads the state of the last accepted `seq` once more, since what it granted
  was kept in memory only (§12). A state older than that one is still ignored.
- `relays` are the sender's current home relays, in its order (§11).
- In the first week after pairing, the joiner's states also confirm the pairing to the inviter
  (§6.3). The first carries no `share`; each later one is the joiner's current state.
- `share` is present while the sender shares with this recipient. `until` is when this
  recipient's access ends (0 = until stopped). A state without `share` ends any earlier grant.
- `color`, optional, is the colour the sender asks viewers to draw its dot in: in this version one of
  `red`, `pink`, `purple`, `deeppurple`, `blue`, `lightblue`, `cyan`, `teal`, `green`, `lime`,
  `yellow`, `orange`, `deeporange` and `brown`. The latest state counts: one without `color` leaves
  the colour to the viewer. A viewer draws a name it does not know as if there were none (§12).
- Encryption: `content = NIP-44(ctl_ck(e), plaintext)`, control class.
- `expiration = epoch_end(e) + 3600`.
- Published to the **recipient's** home relays (its inbox, §11).
- A sender with an active share republishes its state under the new epoch's key at the first
  opportunity after midnight UTC (the stream also rotates then, §9).
- A state is **delivered** once a relay answers `OK true` (§11). Until one does, the sender SHOULD
  send that contact its current state again: whenever a relay connection opens, after a failure on a
  back-off, and after a restart, so it keeps across restarts which contacts wait for one. Within the
  epoch of the state the same event goes again, after it a new state. Without this, a state sent
  offline is lost: a share started then never reaches the recipient, a stop leaves it running, and
  the grant of midnight leaves it on the old stream for a day. Once no relay has accepted any state to
  a contact for 7 days, the sender MAY send them again only while the user has the app open; the 7
  days start again when the contact names other relays, or the user allows one of its relays.
- After a share with a contact ends, once a state without `share` has been delivered to it, the
  sender SHOULD send it its current state once more on a later UTC day. A state can be read only
  until 01:00 UTC the next day, so a recipient offline until then would otherwise go on showing the
  share.
- A sender that deletes a contact erases its channel keys at once (design doc §8.5). If a share with
  that contact ends then, or ended without both of those states having been delivered, it MAY keep
  states without `share` made at that moment, one for each of the next 7 epochs, and send them as
  above: the first until one is delivered, then one on a later day. Only the contact can read them.

## 9. Location stream

A stream is `(stream_sk, stream_key)`: a fresh valid secp256k1 secret and 32 random bytes, both from
the CSPRNG. Only the sharer knows `stream_sk`; current recipients get `stream_pk` and `stream_key` in
their grants.

**Rotation.** The sharer MUST start a new stream whenever:

- a recipient is added, so newcomers cannot decrypt anything published before they were granted;
- a recipient is removed, or its `until` passes;
- a new epoch starts.

A new `until` for a current recipient needs no new stream, only a new state for that recipient.

**Order of a change.** At the moment of the change, T0, the sharer:

1. publishes the states: a grant of the new stream to every remaining recipient and a state without
   `share` to every removed one, in random order;
2. waits until each state has an `OK true` from at least one relay, or 10 s have passed;
3. publishes the `end` of the old stream, and erases the old `stream_sk` and `stream_key`.

The new stream MUST NOT publish its first event before `T0 + δ`, with δ drawn uniformly from 30–120 s
by the CSPRNG.

Stopping the share altogether publishes the same: a state without `share` to every recipient, in
random order, then, after the same wait, the `end`. A removed recipient therefore sees exactly what it
would see if the sharer had stopped: its own state without `share`, among the same number of states,
and the same `end`. What it can still attempt is traffic analysis: a new stream may appear on the
sharer's relays 30–120 s later (design doc, threat T4).

The wait makes it likely that the remaining recipients have their grants before the `end` arrives,
but it cannot guarantee it: states go to each recipient's inbox relays and the `end` to the sharer's
relays. A recipient that sees the `end` first keeps the last position, marked stale, until a state
arrives (§12). States that no relay accepted go again (§8); the `end` does not need to, since a new
grant, or a state without `share`, ends the stream a recipient had too.

A sharer that has lost `stream_sk` (its process died) cannot publish the `end`. The old stream's
last event then simply expires. Recipients treat a new grant, or a state without `share`, as the end
of the stream they had.

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
- published to every relay of the sharer's list that the viewer may use (relay consent, §11).

While nobody watches, a sharer MAY listen only on its listening relay (§11). A signal then starts
faster updates only if the viewer may use that relay; §11 says what the viewer's app does when it
may not.

The sharer treats itself as "watched" until `min(until, now + 120)`. Signals older than 60 s are
ignored. What the sharer does with this (faster updates) is policy, see the design doc (decision D4).
Like a state, a signal from an unconfirmed contact confirms it (§6.3).

## 11. Relays

Every user has 1–4 **home relays**, user-configurable and in the user's order, defaulting to the
list in the design doc. Every relay list a client sends (the invite, steps 2 and 3, states) keeps
that order. A client that keeps a single connection open while idle, such as a sharer that nobody
watches (design doc D17), keeps it to the first relay of its list that it can reach: its
**listening relay**. Its inbox subscription then runs only there. A sharer MAY add a filter for its own
stream's key to that subscription, of the same epoch only (one epoch per connection, below): each event
the relay accepts with `OK true` should then come back over the same connection. When one does not, the
relay accepts events without delivering them, and the client SHOULD listen on the next relay, trying
the first again later (design doc §10.3). Only an event sent for the first time tells: a relay does not
deliver again one it already has, whatever its `OK` says (NIP-01 asks for a prefix such as `duplicate:`
only on a refusal), and a relay that has never sent an event back may simply not do so. Neither proves
anything. A copy counts as come back only once its id and signature check and it matches the filter.
Nor can a REQ the relay never ends with `EOSE` tell: a client SHOULD treat a relay that leaves a REQ
without `EOSE` for long (15 s in the reference) as failing. A client SHOULD remember which of its home
relays have sent an event back, across runs and for as long as they stay among its home relays: one that
stopped delivering before the client started would otherwise never be judged.

| Message | Published to | Read from |
|---|---|---|
| pairing steps 0–3 | inviter's home relays (from the invite) | same |
| state A→B | B's home relays (B's inbox) | B reads its own home relays |
| stream | A's home relays | recipients read A's home relays (from A's `state.relays`) |
| watch signal B→A | A's home relays | A reads its own home relays |

Publishing to another user's relays is limited to those that relay consent allows (below).

**Changing home relays.** Contacts learn a user's home relays only from the `relays` of that user's
states (§8). When the user changes them, the app:

- sends every contact its current state naming the new list. A running share is re-keyed, as for a
  change of recipients (§9), so that its grants, its stream and its listening relay all move to the
  new list; every other contact gets a state without `share`;
- counts each contact as **not moved** until something new from it (a state or a signal) arrives
  through one of the new home relays. A relay in both lists counts: the contact reaches the user there;
- until every contact has moved, and at most through epoch `e_c + 30`, where `e_c` is the epoch of the
  change, also reads its inbox on the previous home relays, which stay allowed (relay consent, below),
  so that what contacts still send there arrives. What arrives there tells nothing of a move;
- sends each contact that has not moved its current state again on each UTC day it runs, unless it has
  already sent that contact a state that day, for as long as the contact has not moved. A state can be
  read only until 01:00 UTC the next day (§8): without the repeats, a contact that did not open its
  app that day would never learn the new list.

A contact that never finished connecting, whose confirmation week (§6.3) is over without one, is left
out of the last three points: it gets no repeats, the previous relays are not read for it, and it is
not shown as not moved (the app offers to remove it instead).

A client that accepts a state naming relays other than those its last state to that contact was
accepted on (the "answer") SHOULD send that contact its current state at once, through the relays now
named and as relay consent allows; if no OK arrives, again as any state (§8), and when the user
allows one of those relays. It sends no answer to a contact it hides. The answer tells the user's app
that the contact has moved. Like any state, it lets the new relays see which of the user's inbox keys
are real (T1).

A contact that has not moved after the 30 days keeps publishing to the old relays, unread, until a
state names the new ones and it answers; the user's app shows it as not moved, so that the user can ask
them to open CoMaps.

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
- **Pairing**, until the invite expires, on the invite's relays: `{"kinds":[30484],"#p":[ipk]}`, and
  for the joiner also `{"kinds":[30484],"authors":[ipk]}` (§6.3).

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
answers `OK true`. Receivers deduplicate by event id, counting an event as received only once its id
and signature have been checked (§12 item 1) and it matches the filter it was sent for. Otherwise a
relay that sends a broken or altered copy first would hide the intact copies that the other relays
deliver.

**Relay consent.** Every relay a phone connects to learns that phone's IP address, hence its rough
location and provider, and when the connection happens. Contacts name relays: a sharer its home
relays in its states, a joiner its relays in step 2, an inviter its relays in the invite and in step
3. A contact who runs one of them would learn your IP address whenever your phone uses it for that
contact. That happens when you view its share or send it watch signals, when you pair with it, and
when you send it states, including when you stop sharing with it. So:

- Implementations MUST NOT connect, to read or to publish, to a relay outside the user's own home
  relays (and the previous ones, until every contact has moved or for 30 days after a change), the
  built-in default list, and relays the user has approved.
- For any other relay a contact names, the app asks, naming the contact: "Bob's location comes
  through relay.example.org, which isn't one of yours. Its operator would see your internet address
  whenever you view Bob." The user can allow the relay, which is remembered per relay and can be
  revoked in the settings; refuse it, which is remembered too, and listed in the settings so that it
  can be allowed later; or put the question off, and the app asks again the next time the relay is
  needed, at most once each time it runs.
- Until approved, a relay is skipped. The app reads, publishes and pairs through the contact's
  remaining relays, if any. Skipping a removed recipient's relay when sending it a state without
  `share` costs nothing: revocation is cryptographic (§9). While none of a contact's relays may be
  used, nothing reaches that contact, and the app shows which relay it would need.
- A viewer takes a sharer's listening relay to be the first of the list in its states. If the viewer
  may not use that relay, its signals cannot reach the sharer while nobody watches, so faster
  updates never start (§10). An app that sends signals MUST then say, when it asks for that relay,
  that live updates need it, and while the relay stays refused, it MUST show that live updates are
  off for that contact (design doc §11.4). The same relay is where an inviter that shares hears its
  joiner's confirmations as they arrive (§6.3).
- Hiding a contact stops every connection made for it: no stream, no signals.

## 12. Receiving rules

Every event must pass all of these checks. Cheap ones may run first, but the signature MUST be
verified before anything is decrypted (as NIP-44 requires):

1. the envelope is well typed: `id` and `pubkey` are 64 and `sig` 128 lowercase hex characters,
   `kind` and `created_at` are integers, `created_at ≥ 0`, `tags` is an array of arrays of strings
   and `content` is a string; the event id equals SHA256 of its serialization, and the BIP-340
   signature is valid;
2. kind and pubkey are among those expected for the subscription, and the `d` tag (and, for the
   joiner's pairing steps, the `p` tag) is as expected. A tag's value is the second element of the
   first tag with that name; other tags are ignored;
3. for kind `30484`: `expiration` is present, 1–10 ASCII digits, and `> now`;
4. `created_at ≤ now + 300`; signals additionally `created_at ≥ now − 60`;
5. NIP-44 decryption with the context's key succeeds (strict base64, MAC, padding), and the
   plaintext is at most 512 bytes of I-JSON (§5) forming an object with a string `"t"`;
6. the fields pass the checks below, and `seq` ordering holds (§8, §9).

Any failure discards the event silently: no error escapes, and no state changes. The exception is
pairing, where §6.3 says when to abort.

**Field checks.** Unknown members are ignored. "Number" means any finite JSON number; "integer" is
defined in §5.

| `t` | Required | Optional |
|---|---|---|
| `state` | `seq` integer ≥ 1; `ts` integer ≥ 0; `relays` per §5 | `share`: an object with `until` an integer ≥ 0, `pk` 64 lowercase hex characters that decode to a valid x-only key, and `key` base64 of exactly 32 bytes. An invalid `share` makes the whole state invalid. `color`: a string of 1–32 bytes; anything else is ignored, the state is not |
| `loc` | `seq` integer ≥ 1; `ts` integer ≥ 0 (ms); `lat` number in [−90, 90]; `lon` number in [−180, 180]; `acc` number ≥ 0 | `spd` number ≥ 0; `brg` number in [0, 360); `alt` number; `low` boolean; `nav` object with `eta` integer ≥ 0, `dist` number ≥ 0 and `dest` string of at most 48 bytes, each optional |
| `end` | `seq` integer ≥ 1; `ts` integer ≥ 0 | — |
| `watch` | `ts` integer ≥ 0; `until` integer ≥ 0 | — |
| `pair1` | — | — |
| `pair2` | `name` per §5; `relays` per §5 | — |
| `pair3` | `ok` boolean; when true: `name`, `relays` as in `pair2`, and `epoch` integer (§6.3) | — |

**Stream keys and positions.**

- A recipient keeps a stream key only while its grant is current. It MUST erase the key when a new
  grant replaces it, when the stream's `end` arrives, and when the grant's `until` passes.
- It also enforces `until` locally, whatever the sharer does.
- Stream keys and positions are kept in memory only (design doc §8.5). After a restart, the
  recipient learns its grants again from its contacts' latest states (§8).
- On an `end`, the recipient keeps the last position, marked stale, for up to 120 s, or until a state
  arrives:
  - with a new grant, it shows the stale position until the new stream's first location;
  - with a state without `share`, it removes the position.

  The `end` and the states travel over different relays, so the `end` can arrive first (§9).

## 13. Obligations (summary)

Anyone can archive ciphertext from public relays. Past positions stay confidential only if every key
that could decrypt them is erased, at both ends:

| Secret | Erased by | When |
|---|---|---|
| `psk`, the pairing secret (`isk`, `jsk`), Noise ephemeral keys and handshake state | both pairing sides | when the pairing ends or aborts (§6.3) |
| roots `k1`, `k2` | both pairing sides | once `CK(e_p)` is derived (§6.3) |
| `mac_key`, the accepted pairing ids | both pairing sides | when the invite expires (§6.3) |
| `CK(e)` | both ends, both directions | at `epoch_end(e) + 3600` (§7) |
| `stream_sk`, `stream_key` | the sharer | when the stream is replaced or ends (§9) |
| `stream_key` | each recipient | when its grant is replaced, at the stream's `end`, when `until` passes (§12) |

Erasure has to reach storage, not only memory. Overwriting or renaming a file does not erase its
old blocks on flash, so implementations encrypt stored state with a key that is replaced, and the
old one destroyed, whenever the state above is erased (design doc §10.4).

Further obligations:

- Pairing: one event per step; watch until the invite expires; abort on a conflict before the pairing
  ends, flag the contact after (§6.3).
- After a change of the share, wait for the states' `OK` (up to 10 s) before publishing the `end` (§9).
- Rotate the stream on every membership change and every epoch, in the order of §9.
- One epoch per connection, decoys in the inbox subscription (§11).
- Never publish anything for a contact the user has not explicitly shared with. After the user
  stops sharing, publish nothing but the final states and the `end`; the final states go again
  until delivered, and once more on a later day (§8). The one exception is the joiner's
  confirmation: a state right after pairing, then its current state on each UTC day it runs,
  through epoch `e_p + 7` (§6.3).
- Send a state that no relay has accepted again until one does, also after a restart; in the
  background, for 7 days without an accepted state at most (§8). A pairing step too, until the invite
  expires (§6.3).
- Connect only to the user's own, the default and approved relays (relay consent, §11); when that
  leaves out a sharer's listening relay, say that live updates are off (§11).
- Invites live at most 24 hours; joiners refuse longer ones (§6.1).
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
| wait for the states' `OK` before an `end` | ≤ 10 s |
| stale position kept after an `end` | ≤ 120 s |
| pairing epoch | `e_p = epoch(now − 300)` at the inviter; the joiner accepts `epoch(now) − 1 ≤ e_p ≤ epoch(now)` |
| joiner's confirmation | a state right after step 3, then one on each UTC day the joiner runs, through epoch `e_p + 7` |
| removal offered for an unconfirmed contact | from `epoch_end(e_p + 7) + 3600` |
| previous home relays read after a change | until every contact has moved (not counting those that never finished connecting), at most through epoch `e_c + 30` |
| echo of an accepted event on the listening relay (optional) | within 15 s of its `OK` |
| invite | 70 bytes plus the relay list (122 bytes with the three default relays) |
| invite lifetime | at most 86400 s; joiners refuse `expires_at` more than 86400 + 300 s ahead |
| JSON integers | within ±(2⁵³ − 1) |
| relay lists | 1–4 `wss://` URLs of ≤ 64 bytes, without `"` or `\` (`ws://` only to loopback) |
| names | 1–64 bytes without control characters |
| dot colour (`color`) | a name of 1–32 bytes, from 14 in this version (§8) |
| authors per REQ filter | ≤ 50 |
| inbox subscription | padded with decoys to a multiple of 8 |

## 15. Test vectors

`vectors/nll1_vectors.json` lists, for one complete scenario, every input and every intermediate value:

- invite bytes and link, both pairing keys, the MAC key and the Noise prologue;
- all four pairing steps (the commitment with its MAC, both Noise messages, the confirmation with the
  inviter's name, relays and pairing epoch), the handshake hash (for debugging only), the split keys
  and the SAS;
- the joiner's confirmation state after pairing;
- channel keys for three epochs in both directions;
- a state with a grant and a state without one;
- a location, a stream end and a watch signal;
- an inbox subscription with its decoys.

Random inputs are given per step in the order they are consumed (`random`: NIP-44 nonce first, then the
BIP-340 auxiliary randomness), so an implementation can reproduce each event byte for byte. Each event
also carries its canonical `serialized` form.

The primitives are checked separately against the published NIP-44 v2, BIP-340, RFC 5869 and Noise
(cacophony) vectors by `test_primitives.py`. The negative and timing cases live in
`test_protocol.py`, and a second implementation should port them too:

- conflicting pairing events, forged or junk steps, and a step 1 meant for another joiner;
- mistyped envelopes whose id and signature still verify (a tag given as a string) and uppercase hex;
- a low-order Noise key;
- plaintexts that break the JSON profile, and states and locations that fail the field checks;
- non-canonical base64;
- a confirmation that expires before the inviter runs, the daily confirmations through epoch
  `e_p + 7`, and the exact moment removal is first offered;
- a watch signal that cannot reach an unwatched sharer's listening relay.

`vectors/profile_cases.json` (made by `make_profile_cases.py`) lists plaintexts with the verdict of
§12 item 5: hand-written cases for each rule of the profile (§5), and mutations of valid plaintexts.
Another implementation must reach the same verdict on every one.
