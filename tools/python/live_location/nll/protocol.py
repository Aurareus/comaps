"""NLL v1 ("Nostr Live Location") reference implementation.

Normative description: docs/LIVE_LOCATION_PROTOCOL.md. This module mirrors it section by
section and is used to generate the published test vectors. Randomness is injected through
`rng` so that vectors are reproducible.

Python cannot reliably wipe memory, so "erase" below means dropping the last reference. The C++
implementation wipes for real (crypto_wipe).
"""

import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field

from . import nip44, noise, primitives as p
from .nostr import Event

KIND_STORED = 30484      # addressable: pairing messages, control messages, location stream
KIND_SIGNAL = 20484      # ephemeral: viewer -> sharer signals
EPOCH_SECONDS = 86400    # epochs are UTC days
SIZE_CONTROL = 512       # pairing and control plaintexts are space-padded to exactly this size
SIZE_STREAM = 256        # location, stream-end and signal plaintexts are padded to this size
MAX_RELAYS = 4           # relay lists carried in messages
MAX_RELAY_URL = 64       # bytes per relay URL
MAX_NAME = 64            # bytes
MAX_DEST = 48            # bytes, nav.dest
MAX_INT = 2 ** 53 - 1    # JSON integers are within +-MAX_INT (I-JSON)
INVITE_VERSION = 1
NOISE_PATTERN = 'NNpsk0'

TTL_LOCATION = 900       # location / stream-end events expire 15 min after creation
CONTROL_GRACE = 3600     # control events expire, and channel keys are erased, 1 h after the end of their epoch
MAX_FUTURE_SKEW = 300    # receivers reject events created more than 5 min in the future
SIGNAL_MAX_AGE = 60      # receivers ignore signals older than this
REKEY_DELAY_MIN = 30     # a replacement stream publishes nothing for a random 30..120 s
REKEY_DELAY_MAX = 120
OK_WAIT = 10             # a sharer waits up to this long for an OK on each state before the old stream's end
END_GRACE = 120          # a viewer keeps an ended stream's last position, marked stale, this long
DECOY_BLOCK = 8          # inbox subscriptions are padded with decoy keys to a multiple of this
MAX_AUTHORS = 50         # authors per REQ filter (nostr-rs-relay times out on 100)
MAX_INVITE_LIFETIME = 86400   # invites live at most a day; joiners refuse longer ones (plus the skew)
CONFIRM_EPOCHS = 7       # the joiner confirms daily through epoch e_p + 7; the inviter then offers removal
DEFAULT_RELAYS = ['wss://nos.lol', 'wss://nostr.mom', 'wss://relay.nostr.net']   # design doc, D5


class PairingAborted(Exception):
    """A pairing step was duplicated or invalid: someone else holds the invite. Stop and tell the user."""


def label(purpose: str) -> bytes:
    return b'nll1:' + purpose.encode('ascii')


def epoch_of(unix_time: int) -> int:
    return unix_time // EPOCH_SECONDS


def epoch_end(epoch: int) -> int:
    return (epoch + 1) * EPOCH_SECONDS


def derive_secp_key(prk: bytes, purpose: str) -> bytes:
    """Deterministic secp256k1 secret: first valid candidate of HKDF-Expand(prk, label || ctr)."""
    for ctr in range(256):
        cand = p.hkdf_expand(prk, label(purpose) + bytes([ctr]), 32)
        if p.secp_is_valid_secret(cand):
            return cand
    raise ValueError('no valid key')  # probability ~2^-32768


def random_secp_key(rng) -> bytes:
    while True:
        sk = rng(32)
        if p.secp_is_valid_secret(sk):
            return sk


def random_below(rng, n: int) -> int:
    """Integer in [0, n) from 32 random bits (the bias, below n / 2^32, is irrelevant for delays and order)."""
    return int.from_bytes(rng(4), 'big') % n


def shuffle(items: list, rng) -> list:
    """Fisher-Yates, in place."""
    for i in range(len(items) - 1, 0, -1):
        j = random_below(rng, i + 1)
        items[i], items[j] = items[j], items[i]
    return items


# --- Plaintext encoding and field checks (§5, §12) ------------------------------------------

def encode_plaintext(obj: dict, size: int) -> bytes:
    text = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    if len(text) > size:
        raise ValueError('plaintext too long: %d' % len(text))
    return text + b' ' * (size - len(text))


def _no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError('duplicate member')
        obj[k] = v
    return obj


def _json_int(text):
    v = int(text)
    if abs(v) > MAX_INT:
        raise ValueError('integer out of range')
    return v


def _json_float(text):
    v = float(text)
    if not math.isfinite(v):
        raise ValueError('number out of range')
    return v


def _not_json(name):
    raise ValueError('not JSON: ' + name)


def _check_strings(x):
    if isinstance(x, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
            raise ValueError('unpaired surrogate')
    elif isinstance(x, dict):
        for k, v in x.items():
            _check_strings(k)
            _check_strings(v)
    elif isinstance(x, list):
        for v in x:
            _check_strings(v)


def parse_json(data: bytes):
    """I-JSON (RFC 7493): valid UTF-8, no duplicate member names, no unpaired surrogates, finite numbers,
    integers within +-(2^53 - 1). Python's json module accepts NaN, Infinity, duplicates and lone
    surrogates by default, and jansson rejects most of them: both must apply the same profile."""
    obj = json.loads(data.decode('utf-8'), object_pairs_hook=_no_duplicates, parse_int=_json_int,
                     parse_float=_json_float, parse_constant=_not_json)
    _check_strings(obj)
    return obj


def is_int(x, lo: int = 0, hi: int = MAX_INT) -> bool:
    """A JSON integer: a number without fraction or exponent. Not a bool, which Python counts as int."""
    return type(x) is int and lo <= x <= hi


def is_number(x, lo: float = -math.inf, hi: float = math.inf) -> bool:
    return type(x) in (int, float) and math.isfinite(x) and lo <= x <= hi


_HEX64 = re.compile(r'[0-9a-f]{64}')
_HEX128 = re.compile(r'[0-9a-f]{128}')
# Printable ASCII but the quote and the backslash, which JSON writes as two bytes each: a relay URL then
# takes as many bytes in a message as it has, and the largest messages fit their size (spec §5).
_URL_TEXT = r'[\x21\x23-\x5b\x5d-\x7e]'
_RELAY_WSS = re.compile(r'wss://' + _URL_TEXT + '+')
_RELAY_WS_LOOPBACK = re.compile(r'ws://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/' + _URL_TEXT + '*)?')


def check_relay_url(url) -> str:
    """wss:// only, URL text as above; ws:// only to a loopback host (a local test relay). Regular expressions
    rather than a URL parser, so that implementations agree byte for byte."""
    if not isinstance(url, str) or len(url.encode('utf-8')) > MAX_RELAY_URL:
        raise ValueError('bad relay url')
    if _RELAY_WSS.fullmatch(url) or _RELAY_WS_LOOPBACK.fullmatch(url):
        return url
    raise ValueError('bad relay url')


def check_relays(relays) -> list:
    if not isinstance(relays, list) or not 1 <= len(relays) <= MAX_RELAYS:
        raise ValueError('bad relay list')
    for r in relays:
        check_relay_url(r)
    return relays


def check_name(name) -> str:
    # No control characters: JSON writes them as six bytes each, and they have no place in a name.
    if (not isinstance(name, str) or not 1 <= len(name.encode('utf-8')) <= MAX_NAME
            or any(ord(c) < 0x20 or ord(c) == 0x7f for c in name)):
        raise ValueError('bad name')
    return name


def check_pubkey_hex(pk) -> str:
    if not (isinstance(pk, str) and len(pk) == 64 and all(c in '0123456789abcdef' for c in pk)
            and p.secp_is_valid_xonly(bytes.fromhex(pk))):
        raise ValueError('bad public key')
    return pk


def check_share(share) -> dict:
    if not isinstance(share, dict) or not is_int(share.get('until')):
        raise ValueError('bad share')
    check_pubkey_hex(share.get('pk'))
    key = share.get('key')
    if not isinstance(key, str) or len(p.b64decode(key)) != 32:
        raise ValueError('bad share key')
    return share


def check_state(body: dict):
    if not (is_int(body.get('seq'), 1) and is_int(body.get('ts'))):
        raise ValueError('bad state')
    check_relays(body.get('relays'))
    if 'share' in body:
        check_share(body['share'])


COLOR_MAX_BYTES = 32


def state_color(state: dict) -> str | None:
    """The sender's dot colour (§8): a name of 1 to 32 bytes, kept whatever it is (an app ignores names it
    does not know). Anything else is ignored, not the state with its grant."""
    color = state.get('color')
    if isinstance(color, str) and 0 < len(color.encode()) <= COLOR_MAX_BYTES:
        return color
    return None


def check_loc(body: dict):
    ok = (is_int(body.get('seq'), 1) and is_int(body.get('ts')) and is_number(body.get('lat'), -90, 90)
          and is_number(body.get('lon'), -180, 180) and is_number(body.get('acc'), 0))
    ok = ok and ('spd' not in body or is_number(body['spd'], 0))
    ok = ok and ('brg' not in body or (is_number(body['brg'], 0) and body['brg'] < 360))
    ok = ok and ('alt' not in body or is_number(body['alt']))
    ok = ok and ('low' not in body or type(body['low']) is bool)
    if ok and 'nav' in body:
        nav = body['nav']
        dest = nav.get('dest', '') if isinstance(nav, dict) else None
        ok = (isinstance(nav, dict) and ('eta' not in nav or is_int(nav['eta']))
              and ('dist' not in nav or is_number(nav['dist'], 0))
              and isinstance(dest, str) and len(dest.encode('utf-8')) <= MAX_DEST)
    if not ok:
        raise ValueError('bad location')


def check_end(body: dict):
    if not (is_int(body.get('seq'), 1) and is_int(body.get('ts'))):
        raise ValueError('bad end')


def check_watch(body: dict):
    if not (is_int(body.get('ts')) and is_int(body.get('until'))):
        raise ValueError('bad signal')


def decode_plaintext(data: bytes) -> dict:
    if len(data) > SIZE_CONTROL:
        raise ValueError('plaintext too long')
    obj = parse_json(data)
    if not isinstance(obj, dict) or not isinstance(obj.get('t'), str):
        raise ValueError('not an NLL message')
    return obj


def seal(obj: dict, size: int, conversation_key: bytes, rng) -> str:
    return nip44.encrypt(encode_plaintext(obj, size), conversation_key, rng(32))


def open_sealed(content: str, conversation_key: bytes) -> dict:
    return decode_plaintext(nip44.decrypt_bytes(content, conversation_key))


def sign_event(sk: bytes, created_at: int, kind: int, tags: list, content: str, rng) -> Event:
    ev = Event(pubkey=p.secp_xonly_pub(sk).hex(), created_at=created_at, kind=kind, tags=tags, content=content)
    return ev.sign(sk, rng(32))


def well_typed(ev: Event) -> bool:
    """NIP-01 field types (§12 item 1): id, pubkey and sig lowercase hex of 64, 64 and 128 characters,
    tags an array of arrays of strings, content a string. Without this, Python would accept uppercase hex
    in a signature, or a string in place of a tag (iterating its characters), which a typed parser refuses."""
    return (isinstance(ev.id, str) and _HEX64.fullmatch(ev.id) is not None
            and isinstance(ev.pubkey, str) and _HEX64.fullmatch(ev.pubkey) is not None
            and isinstance(ev.sig, str) and _HEX128.fullmatch(ev.sig) is not None
            and isinstance(ev.content, str) and isinstance(ev.tags, list)
            and all(isinstance(t, list) and all(isinstance(x, str) for x in t) for t in ev.tags))


def check_event(ev: Event, expected_pubkeys, kind: int, d: str | None, now: int, p_tag: str | None = None) -> bool:
    """Envelope checks every receiver applies before decrypting (§12, items 1-4). `expected_pubkeys` None
    means any author (pairing steps from joiners). A tag's value is the second element of the first tag
    with that name; other tags are ignored."""
    try:
        if not well_typed(ev):
            return False
        if type(ev.kind) is not int or type(ev.created_at) is not int or ev.created_at < 0:
            return False
        if ev.kind != kind or (expected_pubkeys is not None and ev.pubkey not in expected_pubkeys):
            return False
        if not ev.verify():
            return False
        if ev.created_at > now + MAX_FUTURE_SKEW:
            return False
        if d is not None and ev.tag_value('d') != d:
            return False
        if p_tag is not None and ev.tag_value('p') != p_tag:
            return False
        exp = ev.tag_value('expiration')
        if kind == KIND_STORED and not (isinstance(exp, str) and 1 <= len(exp) <= 10 and exp.isascii()
                                        and exp.isdigit() and int(exp) > now):
            return False
        return True
    except (ValueError, TypeError, AttributeError):    # malformed fields from the wire
        return False


# --- Invites ------------------------------------------------------------------------------

@dataclass
class Invite:
    psk: bytes | None
    ipk: bytes          # the inviter's pairing public key (x-only); its secret never leaves the inviter
    expires_at: int
    relays: list

    def encode(self) -> bytes:
        return bytes([INVITE_VERSION]) + self.psk + self.public_fields()

    def public_fields(self) -> bytes:
        out = self.ipk + self.expires_at.to_bytes(4, 'big') + bytes([len(self.relays)])
        for r in self.relays:
            rb = r.encode('utf-8')
            out += bytes([len(rb)]) + rb
        return out

    @staticmethod
    def decode(data: bytes) -> 'Invite':
        if len(data) < 70 or data[0] != INVITE_VERSION:
            raise ValueError('bad invite')
        psk, ipk = data[1:33], data[33:65]
        expires_at = int.from_bytes(data[65:69], 'big')
        n = data[69]
        pos = 70
        relays = []
        for _ in range(n):
            if pos >= len(data):
                raise ValueError('bad invite')
            ln = data[pos]
            relays.append(data[pos + 1:pos + 1 + ln].decode('utf-8'))
            pos += 1 + ln
        if pos != len(data) or not p.secp_is_valid_xonly(ipk):
            raise ValueError('bad invite')
        return Invite(psk, ipk, expires_at, check_relays(relays))

    def link(self) -> str:
        return 'comaps://live/pair#' + p.b64url_nopad_encode(self.encode())

    @staticmethod
    def from_link(link: str) -> 'Invite':
        prefix = 'comaps://live/pair#'
        if not link.startswith(prefix):
            raise ValueError('not an invite link')
        return Invite.decode(p.b64url_nopad_decode(link[len(prefix):]))

    def mac_key(self) -> bytes:
        return p.hkdf_expand(p.hkdf_extract(label('pair'), self.psk), label('pair-mac'), 32)

    def prologue(self, jpk: bytes, c: bytes) -> bytes:
        """Binds the handshake to the invite's public fields and to the one step 0 being answered (its
        author and commitment). The PSK is mixed in by Noise itself."""
        return label('pair') + bytes([INVITE_VERSION]) + self.public_fields() + jpk + c


# --- Contacts and channel keys ------------------------------------------------------------

@dataclass
class Direction:
    """One direction of a pairwise channel: a forward-only chain of epoch keys.

    Only the key of the oldest epoch still needed is stored. advance() replaces it, after which the
    earlier epochs are unrecoverable; at() derives a later epoch without storing it."""
    epoch: int
    chain_key: bytes

    @staticmethod
    def from_root(root: bytes, pairing_epoch: int) -> 'Direction':
        return Direction(pairing_epoch, p.hkdf_expand(root, label('ck') + pairing_epoch.to_bytes(4, 'big'), 32))

    def at(self, epoch: int) -> 'Direction':
        """Chain key for a later (or the same) epoch. Earlier epochs are unreachable by design."""
        if epoch < self.epoch:
            raise ValueError('epoch in the past: keys were ratcheted away')
        ck = self.chain_key
        for _ in range(epoch - self.epoch):
            ck = p.hkdf_expand(ck, label('ck-next'), 32)
        return Direction(epoch, ck)

    def advance(self, epoch: int):
        """Ratchets the stored key forward to `epoch` (no-op if already there), erasing the old one."""
        if epoch > self.epoch:
            later = self.at(epoch)
            self.epoch, self.chain_key = later.epoch, later.chain_key

    def signing_key(self) -> bytes:
        return derive_secp_key(self.chain_key, 'ctl-sign')

    def pubkey(self) -> str:
        return p.secp_xonly_pub(self.signing_key()).hex()

    def conversation_key(self) -> bytes:
        return p.hkdf_expand(self.chain_key, label('ctl-enc'), 32)


@dataclass(eq=False)
class Contact:
    name: str
    relays: list           # the peer's home relays (its inbox and stream outbox), in its order (§11)
    outgoing: Direction    # me -> peer
    incoming: Direction    # peer -> me
    sas: str
    pairing_epoch: int = 0  # e_p (§6.3)
    joiner: bool = False    # this device joined: it scanned or opened the invite
    last_seq_in: dict = field(default_factory=dict)
    seq_out: int = 0       # last state seq sent on the outgoing direction
    last_created_out: int = 0
    verified: bool = False  # this device's user confirmed that both screens showed the same code
    flagged: bool = False  # someone else used the same invite after this pairing finished (§6.3)
    # The peer is known to hold the contact too. An inviter's contact starts False and turns True with the
    # first state or signal that arrives from the joiner (§6.3). False is a label, not a block: sharing with
    # a joiner that never finished leaks nothing, since nobody else holds the channel keys.
    confirmed: bool = True


def ratchet(contact: Contact, now: int):
    """§7: CK(e) is erased once now >= epoch_end(e) + CONTROL_GRACE, in both directions."""
    oldest = epoch_of(now - CONTROL_GRACE)
    contact.outgoing.advance(oldest)
    contact.incoming.advance(oldest)


def sas_digits(k1: bytes) -> str:
    """The 6-digit code. It comes from the key schedule (Split output), which depends only on the PSK and
    the two ephemeral keys, not from the handshake hash, which also covers payloads (§6.4)."""
    v = int.from_bytes(p.hkdf_expand(k1, label('sas'), 4), 'big') % 1000000
    return '%03d %03d' % (v // 1000, v % 1000)


# --- Pairing ------------------------------------------------------------------------------
#
# Each party signs its own pairing events, so nobody can replace or delete the other's:
#   0  joiner  (jsk)  ["p", ipk]   commitment to the joiner's Noise ephemeral key, MACed with the PSK
#   1  inviter (isk)               Noise NNpsk0 message 1 (psk, e)   payload pair1 (nothing else)
#   2  joiner  (jsk)  ["p", ipk]   Noise NNpsk0 message 2 (e, ee)    payload pair2: name, relays
#   3  inviter (isk)               NIP-44 under the confirm key      payload pair3: ok, name, relays, epoch
# ipk is in the invite, so a link holder cannot sign as the inviter. A valid step 0 needs the PSK, so
# only link holders can compete as joiners, and their attempts stay on the relays (under their own
# keys) for both sides to see until the invite expires: before the pairing ends that aborts it, after
# it flags the contact. The commitment and the one-event-per-step rule keep the codes random to a man
# in the middle; the code comes from the keys, so payloads cannot steer it.

def commitment(e_public: bytes) -> bytes:
    return p.sha256(label('commit') + e_public)


def confirm_key(k1: bytes) -> bytes:
    return p.hkdf_expand(k1, label('pair3'), 32)


def step0_content(mac_key: bytes, jpk: bytes, c: bytes) -> str:
    return p.b64encode(c + p.hmac_sha256(mac_key, jpk + c))


def step0_commitment(ev: Event, mac_key: bytes) -> bytes | None:
    """The commitment of a valid step 0, i.e. one whose author holds the invite; None otherwise."""
    try:
        data = p.b64decode(ev.content)
    except (ValueError, UnicodeError):
        return None
    if len(data) != 64:
        return None
    c, tag = data[:32], data[32:]
    if not hmac.compare_digest(tag, p.hmac_sha256(mac_key, bytes.fromhex(ev.pubkey) + c)):
        return None
    return c


def pairing_event(sk: bytes, step: int, invite: Invite, content: str, rng, now: int) -> Event:
    """Joiner steps (0, 2) carry ["p", ipk] so that the inviter can find them; inviter steps do not."""
    tags = [['d', str(step)]] + ([['p', invite.ipk.hex()]] if step in (0, 2) else [])
    tags.append(['expiration', str(invite.expires_at)])
    return sign_event(sk, now, KIND_STORED, tags, content, rng)


def pairing_step(ev: Event, invite: Invite, now: int) -> int | None:
    """The step of an envelope-valid pairing event (§6.3), or None. Steps 1 and 3 must be signed by the
    inviter's key; steps 0 and 2 may come from any key but must carry ["p", ipk]."""
    if now >= invite.expires_at:
        return None
    try:
        d = ev.tag_value('d')
    except (TypeError, AttributeError):
        return None
    if d in ('1', '3'):
        ok = check_event(ev, {invite.ipk.hex()}, KIND_STORED, d, now)
    elif d in ('0', '2'):
        ok = check_event(ev, None, KIND_STORED, d, now, p_tag=invite.ipk.hex())
    else:
        ok = False
    return int(d) if ok else None


@dataclass
class Outcome:
    publish: Event | None = None       # publish this event now (and retransmit the same one if needed)
    show_code: dict | None = None      # show the code (inviter: with the joiner's name; ask to decide)
    contact: 'Contact | None' = None   # the pairing finished with this contact
    declined: bool = False             # the inviter declined
    flagged: bool = False              # a conflict after the pairing finished: the contact is now flagged


class Joiner:
    """The party that scanned/opened the invite (Noise responder)."""

    def __init__(self, invite: Invite, name: str, relays: list, rng, now: int):
        if now >= invite.expires_at:
            raise ValueError('invite expired')
        if invite.expires_at > now + MAX_INVITE_LIFETIME + MAX_FUTURE_SKEW:
            raise ValueError('invite lifetime over a day: it would keep this phone watching its relays')
        self.invite, self.name, self.relays = invite, check_name(name), check_relays(relays)
        self.mac_key = invite.mac_key()
        self.jsk = random_secp_key(rng)     # signs steps 0 and 2
        self.jpk = p.secp_xonly_pub(self.jsk)
        self.e = rng(32)                    # used in exactly one step 2, never again
        self.c = commitment(p.x25519_public(self.e))
        self.hs = noise.HandshakeState(NOISE_PATTERN, False, invite.prologue(self.jpk, self.c), invite.psk, self.e)
        self.step0 = None
        self.accepted = {}                  # step -> id of the one inviter event accepted for it
        self.step2 = None
        self.k1 = self.k2 = None
        self.sas = None
        self.contact = None
        self.done = False

    def commit_event(self, rng, now: int) -> Event:
        """Step 0, made once: a retransmission resends this same event (an implementation that persists the
        pairing state records it before publishing)."""
        if self.step0 is None:
            if self.jsk is None:
                raise ValueError('aborted')
            self.step0 = pairing_event(self.jsk, 0, self.invite, step0_content(self.mac_key, self.jpk, self.c),
                                       rng, now)
        return self.step0

    def _conflict(self, why: str) -> Outcome:
        if not self.done:
            self.abort()
            raise PairingAborted(why)
        if self.contact is not None:
            self.contact.flagged = True
        return Outcome(flagged=True)

    def on_event(self, ev: Event, rng, now: int) -> Outcome | None:
        """Every event of the two pairing subscriptions, the joiner's own included, until the invite expires.
        Returns what to do, None to ignore the event, or raises PairingAborted."""
        if self.mac_key is None:
            return None                                 # aborted or expired
        step = pairing_step(ev, self.invite, now)
        if step is None:
            return None
        if step in (0, 2):
            if ev.pubkey == self.jpk.hex():
                return None                             # our own (nobody else can sign them)
            if step == 0 and step0_commitment(ev, self.mac_key) is not None:
                return self._conflict('another device used this invite')
            return None                                 # no proof of the PSK: not evidence of anything
        prev = self.accepted.get(step)
        if prev is not None:
            return None if prev == ev.id else self._conflict('the inviter sent a second step %d' % step)
        if self.done:
            return None
        if step == 1:
            self.accepted[1] = ev.id
            try:
                info = decode_plaintext(self.hs.read_message(p.b64decode(ev.content)))
                if info.get('t') != 'pair1':
                    raise ValueError('unexpected message')
                # Writing step 2 computes ee, which fails on a low-order key in step 1: that must abort
                # like any other invalid step 1, not escape as a plain error.
                payload = encode_plaintext({'t': 'pair2', 'name': self.name, 'relays': self.relays}, SIZE_CONTROL)
                message2 = self.hs.write_message(payload)
            except Exception:
                return self._conflict('the inviter answered someone else, or step 1 is invalid')
            self.step2 = pairing_event(self.jsk, 2, self.invite, p.b64encode(message2), rng, now)
            _, _, self.k1, self.k2 = self.hs.ss.split()
            self.handshake_hash = self.hs.handshake_hash()    # for vectors and debugging only
            self.hs = self.e = None
            self.sas = sas_digits(self.k1)
            return Outcome(publish=self.step2, show_code={'sas': self.sas})
        if self.step2 is None:
            raise ValueError('out of order')            # held until step 2 has been sent (§6.3)
        self.accepted[3] = ev.id
        try:
            body = open_sealed(ev.content, confirm_key(self.k1))
            if body.get('t') != 'pair3' or type(body.get('ok')) is not bool:
                raise ValueError('unexpected message')
            if body['ok']:
                e_p = body.get('epoch')
                if not (is_int(e_p) and epoch_of(now) - 1 <= e_p <= epoch_of(now)):
                    raise ValueError('implausible pairing epoch')
                contact = Contact(check_name(body.get('name')), check_relays(body.get('relays')),
                                  Direction.from_root(self.k2, e_p), Direction.from_root(self.k1, e_p), self.sas,
                                  pairing_epoch=e_p, joiner=True)
        except Exception:
            return self._conflict('invalid step 3')
        self.done = True
        self._erase_secrets()
        if not body['ok']:
            return Outcome(declined=True)
        self.contact = contact
        # Completion has to be two-sided: the inviter's contact exists from its decision on, but only a
        # message on the new channel tells it that the joiner got step 3. This state is the first such
        # message; confirmation_due() asks for one a day through epoch e_p + 7 (§6.3).
        return Outcome(contact=contact, publish=state_event(contact, self.relays, None, rng, now))

    def _erase_secrets(self):
        """The pairing ended: keep only what watching for conflicts needs until the invite expires (the MAC
        key and public data). The roots k1/k2 go too: whoever holds them can derive every chain key."""
        self.invite.psk = None
        self.jsk = self.e = self.hs = self.k1 = self.k2 = None

    def abort(self):
        self._erase_secrets()
        self.mac_key = None

    def expire(self):
        """At invite expiry: nothing is left to watch."""
        self.abort()


class Inviter:
    """The party that showed the invite (Noise initiator)."""

    def __init__(self, relays: list, rng, now: int, lifetime: int = 600):
        if not 0 < lifetime <= MAX_INVITE_LIFETIME:
            raise ValueError('invite lifetime must be at most a day')
        psk = rng(32)
        self.isk = random_secp_key(rng)     # signs steps 1 and 3; its public key goes into the invite
        self.invite = Invite(psk, p.secp_xonly_pub(self.isk), now + lifetime, check_relays(relays))
        self.mac_key = self.invite.mac_key()
        self.e = rng(32)
        self.accepted = {}                  # step -> id of the one joiner event accepted for it
        self.jpk = None                     # author of the accepted step 0
        self.commit = None
        self.hs = None
        self.request = None
        self.k1 = self.k2 = None
        self.sas = None
        self.contact = None
        self.decided = False

    def _conflict(self, why: str) -> Outcome:
        if not self.decided:
            self.abort()
            raise PairingAborted(why)
        if self.contact is not None:
            self.contact.flagged = True
        return Outcome(flagged=True)

    def on_event(self, ev: Event, rng, now: int) -> Outcome | None:
        """Every event of the pairing subscription until the invite expires."""
        if self.mac_key is None:
            return None                                 # aborted or expired
        step = pairing_step(ev, self.invite, now)
        if step not in (0, 2):
            return None
        if step == 0:
            c = step0_commitment(ev, self.mac_key)
            if c is None or self.accepted.get(0) == ev.id:
                return None
            if 0 in self.accepted or self.decided:
                return self._conflict('another device used this invite')
            self.accepted[0], self.jpk, self.commit = ev.id, bytes.fromhex(ev.pubkey), c
            self.hs = noise.HandshakeState(NOISE_PATTERN, True, self.invite.prologue(self.jpk, c), self.invite.psk,
                                           self.e)
            payload = encode_plaintext({'t': 'pair1'}, SIZE_CONTROL)
            return Outcome(publish=pairing_event(self.isk, 1, self.invite, p.b64encode(self.hs.write_message(payload)),
                                                 rng, now))
        if self.jpk is None or ev.pubkey != self.jpk.hex():
            return None                                 # only the accepted joiner's step 2 counts
        prev = self.accepted.get(2)
        if prev is not None:
            return None if prev == ev.id else self._conflict('a second, different step 2')
        self.accepted[2] = ev.id
        try:
            data = p.b64decode(ev.content)
            if not hmac.compare_digest(commitment(data[:noise.DHLEN]), self.commit):
                raise ValueError('step 2 does not open the commitment')
            info = decode_plaintext(self.hs.read_message(data))
            if info.get('t') != 'pair2':
                raise ValueError('unexpected message')
            check_name(info.get('name'))
            check_relays(info.get('relays'))
        except Exception:
            return self._conflict('invalid step 2')
        _, _, self.k1, self.k2 = self.hs.ss.split()
        self.handshake_hash = self.hs.handshake_hash()    # for vectors and debugging only
        self.hs = self.e = None
        self.request = info
        self.sas = sas_digits(self.k1)
        return Outcome(show_code={'name': info['name'], 'relays': info['relays'], 'sas': self.sas})

    def decide(self, accept: bool, name: str, relays: list, rng, now: int) -> Outcome:
        """After the user's decision. The inviter's name, relays and the pairing epoch travel in step 3, under
        a key that needs the ee exchange. e_p lags by the accepted clock skew, so that it is never in the
        joiner's future (§6.3)."""
        if self.request is None or self.decided or self.k1 is None:
            raise ValueError('out of order or aborted')
        if now >= self.invite.expires_at:
            raise ValueError('invite expired: relays would refuse step 3, and the joiner stops at expiry')
        self.decided = True
        e_p = epoch_of(now - MAX_FUTURE_SKEW)
        body = {'t': 'pair3', 'ok': True, 'name': check_name(name), 'relays': check_relays(relays), 'epoch': e_p} \
            if accept else {'t': 'pair3', 'ok': False}
        ev = pairing_event(self.isk, 3, self.invite, seal(body, SIZE_CONTROL, confirm_key(self.k1), rng), rng, now)
        if accept:
            self.contact = Contact(self.request['name'], self.request['relays'], Direction.from_root(self.k1, e_p),
                                   Direction.from_root(self.k2, e_p), self.sas, pairing_epoch=e_p, confirmed=False)
        self._erase_secrets()
        return Outcome(publish=ev, contact=self.contact, declined=not accept)

    def _erase_secrets(self):
        self.invite.psk = None
        self.isk = self.e = self.hs = self.k1 = self.k2 = None

    def abort(self):
        self._erase_secrets()
        self.mac_key = None

    def expire(self):
        self.abort()


# --- Control channel ----------------------------------------------------------------------
#
# Each direction of a channel has a single addressable slot holding the sender's *current state*
# towards that contact: its home relays and, while it shares with the contact, the stream grant.
# A state without "share" ends any previous grant.

def control_event(contact: Contact, body: dict, rng, now: int) -> Event:
    # Addressable replacement keeps the event with the higher created_at, and on a tie the one with
    # the lower id: created_at must strictly increase per channel or a same-second update may be lost.
    ratchet(contact, now)
    created_at = max(now, contact.last_created_out + 1)
    contact.last_created_out = created_at
    # The stored key can be ahead of the clock if the clock was set back: sign with it rather than fail.
    d = contact.outgoing.at(max(epoch_of(created_at), contact.outgoing.epoch))
    return sign_event(d.signing_key(), created_at, KIND_STORED,
                      [['d', ''], ['expiration', str(epoch_end(d.epoch) + CONTROL_GRACE)]],
                      seal(body, SIZE_CONTROL, d.conversation_key(), rng), rng)


def state_body(seq: int, now: int, relays: list, share: dict | None = None, color: str | None = None) -> dict:
    body = {'t': 'state', 'seq': seq, 'ts': now, 'relays': check_relays(relays)}
    if share is not None:
        body['share'] = share
    if color is not None:
        body['color'] = color
    return body


def state_event(contact: Contact, relays: list, share: dict | None, rng, now: int, color: str | None = None) -> Event:
    contact.seq_out += 1
    return control_event(contact, state_body(contact.seq_out, now, relays, share, color), rng, now)


def share_grant(until: int, stream_pk: str, stream_key: bytes) -> dict:
    """`until` is when this recipient's access ends (unix seconds), 0 meaning until stopped."""
    return {'until': until, 'pk': stream_pk, 'key': p.b64encode(stream_key)}


def incoming_keys(contact: Contact, now: int) -> dict:
    """Keys that may sign a contact's events towards me: epochs e-1..e+1 (clock skew), minus erased ones."""
    ratchet(contact, now)
    e = epoch_of(now)
    keys = {}
    for epoch in (e - 1, e, e + 1):
        if epoch >= contact.incoming.epoch:
            d = contact.incoming.at(epoch)
            keys[d.pubkey()] = d
    return keys


def read_control(contact: Contact, ev: Event, now: int) -> dict | None:
    """Receiver side: a state event from `contact`, or None. Any failure discards the event silently (§12)."""
    candidates = incoming_keys(contact, now)
    if not check_event(ev, set(candidates), KIND_STORED, '', now):
        return None
    try:
        body = open_sealed(ev.content, candidates[ev.pubkey].conversation_key())
        if body.get('t') != 'state':
            return None
        check_state(body)
    except Exception:
        return None
    if body['seq'] <= contact.last_seq_in.get('state', 0):
        return None  # replay of an older state, e.g. a grant re-served after it was ended
    contact.last_seq_in['state'] = body['seq']
    contact.confirmed = True
    return body


def confirmation_due(contact: Contact, now: int) -> bool:
    """Joiner side (§6.3): whether to send the current state to the inviter now. Only a message on the new
    channel tells the inviter that the pairing finished, and a state is readable only until an hour after
    the end of its UTC day, a span in which the inviter's app may not run at all. So through epoch
    e_p + 7, every UTC day on which the joiner's app runs carries one state. The caller sends its CURRENT
    state (Sharer.current_state): a state without `share` would end a share with the inviter.

    Not a longer-lived key instead: the inviter would query that same key every day, which links its
    daily connections (§11)."""
    e = epoch_of(now)
    return contact.joiner and e <= contact.pairing_epoch + CONFIRM_EPOCHS and epoch_of(contact.last_created_out) < e


def offer_removal(contact: Contact, now: int) -> bool:
    """Inviter side (§6.3): a contact still waiting once the last state the joiner owed has expired. Before
    that, "waiting" is only a label."""
    return not contact.confirmed and now >= epoch_end(contact.pairing_epoch + CONFIRM_EPOCHS) + CONTROL_GRACE


# --- Subscriptions ------------------------------------------------------------------------

def split_relays(named: list, trusted: set) -> tuple:
    """Relay consent (§11): (the relays named by a contact that the app may use now, those it must first ask
    the user about). `trusted` holds the user's own home relays, the built-in defaults and the relays the
    user approved earlier. The same rule covers reading a contact's stream, publishing to its inbox, sending
    it signals and pairing through an invite's relays: whoever runs a relay sees the IP addresses that
    connect to it."""
    return [r for r in named if r in trusted], [r for r in named if r not in trusted]


def missing_listening_relay(relays: list, trusted: set) -> str | None:
    """Viewer side (§10, §11): the relay that live updates need, if the viewer may not use it. While nobody
    watches, a sharer listens only on its listening relay: the first relay of the list in its states, unless
    it cannot reach that one. Watch signals go only to relays the viewer may use, so the app asks for this
    relay, saying that live updates need it, and while it stays refused shows that they are off (design
    doc §11.4). It is also where an inviter that shares hears its joiner's confirmations (§6.3)."""
    return None if relays[0] in trusted else relays[0]


def decoy_keys(decoy_seed: bytes, epoch: int, count: int) -> list:
    """Stable for the whole epoch, so that reconnecting does not reveal which keys are real (§11)."""
    out = []
    for i in range(count):
        prk = p.hkdf_expand(decoy_seed, label('decoy') + epoch.to_bytes(4, 'big') + i.to_bytes(4, 'big'), 32)
        out.append(p.secp_xonly_pub(derive_secp_key(prk, 'decoy-sign')).hex())
    return out


def inbox_filters(contacts: list, decoy_seed: bytes, epoch: int, now: int) -> list:
    """REQ filters for one's own home relays: every contact's channel key of ONE epoch, padded with decoys
    and sorted, for both states and signals. A connection never mixes epochs (§11). A contact whose chain
    is already past `epoch` (the clock was set back) has no key for it and is left out, never the cause of
    a failure for all the others."""
    real = [c.incoming.at(epoch).pubkey() for c in contacts if c.incoming.epoch <= epoch]
    if not real:
        return []
    padded = -(-len(real) // DECOY_BLOCK) * DECOY_BLOCK
    authors = sorted(real + decoy_keys(decoy_seed, epoch, padded - len(real)))
    filters = []
    for i in range(0, len(authors), MAX_AUTHORS):
        chunk = authors[i:i + MAX_AUTHORS]
        filters.append({'kinds': [KIND_STORED], 'authors': chunk})
        filters.append({'kinds': [KIND_SIGNAL], 'authors': chunk, 'since': now - SIGNAL_MAX_AGE})
    return filters


# --- Location stream ----------------------------------------------------------------------

@dataclass
class Stream:
    secret: bytes      # signing key (sharer only)
    key: bytes         # NIP-44 conversation key (shared with current recipients)
    seq: int = 0
    last_created: int = 0

    @staticmethod
    def create(rng) -> 'Stream':
        return Stream(random_secp_key(rng), rng(32))

    def pubkey(self) -> str:
        return p.secp_xonly_pub(self.secret).hex()

    def _created_at(self, now: int) -> int:
        # Strictly increasing per stream, see control_event().
        self.last_created = max(now, self.last_created + 1)
        return self.last_created

    def location_event(self, fix: dict, rng, now: int) -> Event:
        self.seq += 1
        body = {'t': 'loc', 'seq': self.seq}
        body.update(fix)
        created_at = self._created_at(now)
        return sign_event(self.secret, created_at, KIND_STORED,
                          [['d', ''], ['expiration', str(created_at + TTL_LOCATION)]],
                          seal(body, SIZE_STREAM, self.key, rng), rng)

    def end_event(self, rng, now: int) -> Event:
        """The same whatever the reason (stop, removal, time limit, re-key): a removed recipient must not
        learn whether the sharer carries on with others."""
        self.seq += 1
        created_at = self._created_at(now)
        return sign_event(self.secret, created_at, KIND_STORED,
                          [['d', ''], ['expiration', str(created_at + TTL_LOCATION)]],
                          seal({'t': 'end', 'seq': self.seq, 'ts': now}, SIZE_STREAM, self.key, rng), rng)


_STREAM_CHECKS = {'loc': check_loc, 'end': check_end}


def read_stream(grant: dict, ev: Event, last_seq: int, now: int) -> dict | None:
    """A location or end of the granted stream, or None. Any failure discards the event silently (§12)."""
    if not check_event(ev, {grant['pk']}, KIND_STORED, '', now):
        return None
    try:
        body = open_sealed(ev.content, p.b64decode(grant['key']))
        _STREAM_CHECKS[body.get('t')](body)
    except Exception:
        return None
    return body if body['seq'] > last_seq else None


@dataclass
class Rekey:
    """What a change of the share publishes, in two phases: first the states, then, once each state has an
    OK from at least one relay (or OK_WAIT has passed), the old stream's end."""
    states: list
    end: Event | None = None


class Sharer:
    """Sharer side of §9: one stream for all current recipients, replaced whenever anyone is added or
    removed (including by `until`) and at every new epoch. Nothing here is written to disk."""

    def __init__(self, relays: list, color: str | None = None):
        self.relays = check_relays(relays)
        self.color = color       # the dot colour the states carry (§8), or None
        self.grants = {}         # Contact -> until (0 = until stopped)
        self.stream = None
        self.stream_epoch = None
        self.not_before = 0

    def _states(self, removed: list, rng, now: int) -> list:
        evs = [state_event(c, self.relays, share_grant(u, self.stream.pubkey(), self.stream.key), rng, now,
                           self.color) for c, u in self.grants.items()]
        evs += [state_event(c, self.relays, None, rng, now, self.color) for c in removed]
        return shuffle(evs, rng)

    def start(self, grants: dict, rng, now: int) -> Rekey:
        if self.stream is not None:
            raise ValueError('already sharing')
        self.grants = dict(grants)
        self.stream, self.stream_epoch, self.not_before = Stream.create(rng), epoch_of(now), now
        return Rekey(self._states([], rng, now))

    def change(self, grants: dict, rng, now: int) -> Rekey:
        """A new recipient set (or the same one at a new epoch): every state (new grants and share-less ones,
        shuffled), then the old stream's end. The new stream stays silent until `not_before`."""
        if not grants:
            return self.stop(rng, now)
        removed = [c for c in self.grants if c not in grants]
        old = self.stream
        self.grants = dict(grants)
        self.stream, self.stream_epoch = Stream.create(rng), epoch_of(now)
        rekey = Rekey(self._states(removed, rng, now), old.end_event(rng, now))
        self.not_before = now + REKEY_DELAY_MIN + random_below(rng, REKEY_DELAY_MAX - REKEY_DELAY_MIN + 1)
        return rekey

    def extend(self, contact: Contact, until: int, rng, now: int) -> Event:
        """A new `until` for a CURRENT recipient: same stream, no re-key. Adding someone goes through
        change(): a newcomer must not be able to read what was published before it was granted (§9)."""
        if contact not in self.grants:
            raise ValueError('not a current recipient: use change()')
        if not (until == 0 or until > now):
            raise ValueError('until in the past: use change()')
        self.grants[contact] = until
        return self.current_state(contact, rng, now)

    def current_state(self, contact: Contact, rng, now: int) -> Event:
        """This device's current state towards `contact`, sent again, e.g. as the joiner's daily confirmation
        (§6.3). It carries the grant while `contact` is a recipient, so that sending it never ends a share."""
        until = self.grants.get(contact)
        share = None if until is None else share_grant(until, self.stream.pubkey(), self.stream.key)
        return state_event(contact, self.relays, share, rng, now, self.color)

    def stop(self, rng, now: int) -> Rekey:
        """Same shape as change() seen from a removed recipient: states (shuffled), then the end."""
        removed = list(self.grants)
        self.grants = {}
        rekey = Rekey(self._states(removed, rng, now), self.stream.end_event(rng, now))
        self.stream = None
        return rekey

    def tick(self, rng, now: int) -> Rekey | None:
        """Time limits and the epoch change."""
        if self.stream is None:
            return None
        current = {c: u for c, u in self.grants.items() if u == 0 or u > now}
        if len(current) != len(self.grants) or epoch_of(now) != self.stream_epoch:
            return self.change(current, rng, now)
        return None

    def location(self, fix: dict, rng, now: int) -> Event | None:
        if self.stream is None or now < self.not_before:
            return None
        return self.stream.location_event(fix, rng, now)


class Following:
    """Viewer side of one contact's share: the current grant and the latest position, in memory only.

    A replaced or ended stream key is dropped at once (§12). The last position survives an end, marked
    stale, for END_GRACE: states and the end travel over different relays, so the end can arrive before
    the grant of its replacement."""

    def __init__(self):
        self.grant = None
        self.last_seq = 0
        self.position = None
        self.stale = False
        self.ended_at = None
        self.color = None

    def on_state(self, state: dict, now: int):
        self.color = state_color(state)
        share = state.get('share')
        if share is None or (share['until'] and share['until'] <= now):
            self.stop()
        elif self.grant is None or share['pk'] != self.grant['pk']:
            self.grant, self.last_seq, self.ended_at = share, 0, None   # a new stream
            self.stale = self.position is not None                      # until its first location
        else:
            self.grant = share                                          # e.g. a new `until`

    def on_stream(self, ev: Event, now: int) -> dict | None:
        if self.grant is None:
            return None
        if self.grant['until'] and self.grant['until'] <= now:
            self.stop()
            return None
        body = read_stream(self.grant, ev, self.last_seq, now)
        if body is None:
            return None
        self.last_seq = body['seq']
        if body['t'] == 'end':
            self.grant, self.last_seq = None, 0                         # erase the stream key
            self.stale, self.ended_at = self.position is not None, now
        else:
            self.position, self.stale = body, False
        return body

    def tick(self, now: int):
        if self.grant is None and self.ended_at is not None and now >= self.ended_at + END_GRACE:
            self.stop()

    def stop(self):
        self.grant, self.last_seq, self.position, self.stale, self.ended_at = None, 0, None, False, None


# --- Signals (viewer -> sharer, ephemeral) ------------------------------------------------

def watch_signal(contact: Contact, until: int, rng, now: int) -> Event:
    ratchet(contact, now)
    d = contact.outgoing.at(max(epoch_of(now), contact.outgoing.epoch))
    return sign_event(d.signing_key(), now, KIND_SIGNAL, [],
                      seal({'t': 'watch', 'ts': now, 'until': until}, SIZE_STREAM, d.conversation_key(), rng), rng)


def read_signal(contact: Contact, ev: Event, now: int) -> dict | None:
    keys = incoming_keys(contact, now)
    if not check_event(ev, set(keys), KIND_SIGNAL, None, now) or ev.created_at < now - SIGNAL_MAX_AGE:
        return None
    try:
        body = open_sealed(ev.content, keys[ev.pubkey].conversation_key())
        if body.get('t') != 'watch':
            return None
        check_watch(body)
    except Exception:
        return None
    contact.confirmed = True        # only a joiner that finished holds this channel (§6.3)
    return body


class TestRng:
    """Deterministic randomness for test vectors: HKDF-Expand(seed, 'nll1:test-rng' || counter)."""

    def __init__(self, seed: bytes):
        self.prk = p.hkdf_extract(b'nll1:test-rng', seed)
        self.counter = 0

    def __call__(self, n: int) -> bytes:
        self.counter += 1
        return p.hkdf_expand(self.prk, self.counter.to_bytes(8, 'big'), n)


def now() -> int:
    return int(time.time())
