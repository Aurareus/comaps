"""NLL v1 ("Nostr Live Location") reference implementation.

Normative description: docs/LIVE_LOCATION_PROTOCOL.md. This module mirrors it section by
section and is used to generate the published test vectors. Randomness is injected through
`rng` so that vectors are reproducible.
"""

import hmac
import json
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
INVITE_VERSION = 1
NOISE_PATTERN = 'NNpsk0'

TTL_LOCATION = 900       # location / stream-end events expire 15 min after creation
CONTROL_GRACE = 3600     # control events expire 1 h after the end of their epoch
MAX_FUTURE_SKEW = 300    # receivers reject events created more than 5 min in the future


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


# --- Plaintext encoding -------------------------------------------------------------------

def encode_plaintext(obj: dict, size: int) -> bytes:
    text = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    if len(text) > size:
        raise ValueError('plaintext too long: %d' % len(text))
    return text + b' ' * (size - len(text))


def check_relays(relays) -> list:
    if not isinstance(relays, list) or not 1 <= len(relays) <= MAX_RELAYS:
        raise ValueError('bad relay list')
    for r in relays:
        if not isinstance(r, str) or not r.startswith(('wss://', 'ws://')) or len(r.encode('utf-8')) > MAX_RELAY_URL:
            raise ValueError('bad relay url')
    return relays


MAX_NAME = 64           # bytes


def check_name(name) -> str:
    if not isinstance(name, str) or not 1 <= len(name.encode('utf-8')) <= MAX_NAME:
        raise ValueError('bad name')
    return name


def decode_plaintext(data: bytes) -> dict:
    if len(data) > SIZE_CONTROL:
        raise ValueError('plaintext too long')
    obj = json.loads(data.decode('utf-8'))
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


def check_event(ev: Event, expected_pubkeys, kind: int, d: str | None, now: int) -> bool:
    """Envelope checks every receiver applies before decrypting (spec section 'Receiving')."""
    if ev.kind != kind or ev.pubkey not in expected_pubkeys or not ev.verify():
        return False
    if ev.created_at > now + MAX_FUTURE_SKEW:
        return False
    if d is not None and ev.tag_value('d') != d:
        return False
    exp = ev.tag_value('expiration')
    if kind == KIND_STORED and (exp is None or not (exp.isascii() and exp.isdigit()) or int(exp) <= now):
        return False
    return True


# --- Invites ------------------------------------------------------------------------------

@dataclass
class Invite:
    psk: bytes
    expires_at: int
    relays: list

    def encode(self) -> bytes:
        return bytes([INVITE_VERSION]) + self.psk + self._public_fields()

    def _public_fields(self) -> bytes:
        out = self.expires_at.to_bytes(4, 'big') + bytes([len(self.relays)])
        for r in self.relays:
            rb = r.encode('utf-8')
            out += bytes([len(rb)]) + rb
        return out

    @staticmethod
    def decode(data: bytes) -> 'Invite':
        if len(data) < 38 or data[0] != INVITE_VERSION:
            raise ValueError('bad invite')
        psk = data[1:33]
        expires_at = int.from_bytes(data[33:37], 'big')
        n = data[37]
        pos = 38
        relays = []
        for _ in range(n):
            ln = data[pos]
            relays.append(data[pos + 1:pos + 1 + ln].decode('utf-8'))
            pos += 1 + ln
        if pos != len(data):
            raise ValueError('bad invite')
        return Invite(psk, expires_at, check_relays(relays))

    def link(self) -> str:
        return 'comaps://live/pair#' + p.b64url_nopad_encode(self.encode())

    @staticmethod
    def from_link(link: str) -> 'Invite':
        prefix = 'comaps://live/pair#'
        if not link.startswith(prefix):
            raise ValueError('not an invite link')
        return Invite.decode(p.b64url_nopad_decode(link[len(prefix):]))

    def rendezvous_key(self) -> bytes:
        return derive_secp_key(p.hkdf_extract(label('rv'), self.psk), 'rv-sign')

    def prologue(self) -> bytes:
        """Binds the handshake to the invite's public fields (the PSK is mixed in by Noise itself)."""
        return label('pair') + bytes([INVITE_VERSION]) + self._public_fields()


# --- Contacts and channel keys ------------------------------------------------------------

@dataclass
class Direction:
    """One direction of a pairwise channel: a forward-only chain of epoch keys."""
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

    def signing_key(self) -> bytes:
        return derive_secp_key(self.chain_key, 'ctl-sign')

    def pubkey(self) -> str:
        return p.secp_xonly_pub(self.signing_key()).hex()

    def conversation_key(self) -> bytes:
        return p.hkdf_expand(self.chain_key, label('ctl-enc'), 32)


@dataclass
class Contact:
    name: str
    relays: list           # the peer's home relays (its inbox and stream outbox)
    outgoing: Direction    # me -> peer
    incoming: Direction    # peer -> me
    sas: str
    last_seq_in: dict = field(default_factory=dict)
    last_created_out: int = 0


def sas_digits(handshake_hash: bytes) -> str:
    v = int.from_bytes(p.hkdf_expand(handshake_hash, label('sas'), 4), 'big') % 1000000
    return '%03d %03d' % (v // 1000, v % 1000)


# --- Pairing ------------------------------------------------------------------------------
#
# Four rendezvous events, all kind 30484 signed by the invite's rendezvous key and published to the
# inviter's relays, with d = "0".."3":
#   0  joiner  -> inviter  commitment SHA256(label('commit') || joiner's Noise ephemeral public key)
#   1  inviter -> joiner   Noise NNpsk0 message 1 (psk, e)   payload pair1: name, relays, epoch
#   2  joiner  -> inviter  Noise NNpsk0 message 2 (e, ee)    payload pair2: name, relays
#   3  inviter -> joiner   NIP-44 under the confirm key      payload pair3: ok
# The inviter is the Noise initiator. The joiner commits to its ephemeral key before it sees the
# inviter's, so a man in the middle who knows the PSK cannot choose its own keys after the fact to
# make the two 6-digit codes match: each code is random to it (match probability 1e-6 per attempt).

def commitment(e_public: bytes) -> bytes:
    return p.sha256(label('commit') + e_public)


def confirm_key(k_i2r: bytes) -> bytes:
    return p.hkdf_expand(k_i2r, label('pair3'), 32)


def rendezvous_event(rv_sk: bytes, step: int, content: str, invite: Invite, rng, now: int) -> Event:
    return sign_event(rv_sk, now, KIND_STORED, [['d', str(step)], ['expiration', str(invite.expires_at)]], content,
                      rng)


def check_rendezvous(ev: Event, rv_sk: bytes, step: int, invite: Invite, now: int):
    if now >= invite.expires_at or not check_event(ev, {p.secp_xonly_pub(rv_sk).hex()}, KIND_STORED, str(step), now):
        raise ValueError('bad envelope')


class Joiner:
    """The party that scanned/opened the invite (Noise responder)."""

    def __init__(self, invite: Invite, name: str, relays: list, rng, now: int):
        if now >= invite.expires_at:
            raise ValueError('invite expired')
        self.invite, self.name, self.relays = invite, check_name(name), check_relays(relays)
        self.e = rng(32)
        self.hs = noise.HandshakeState(NOISE_PATTERN, False, invite.prologue(), invite.psk, self.e)
        self.rv_sk = invite.rendezvous_key()
        self.peer = None
        self.sas = None

    def commit_event(self, rng, now: int) -> Event:
        return rendezvous_event(self.rv_sk, 0, p.b64encode(commitment(p.x25519_public(self.e))), self.invite, rng, now)

    def on_message1(self, ev: Event, now: int) -> dict:
        check_rendezvous(ev, self.rv_sk, 1, self.invite, now)
        info = decode_plaintext(self.hs.read_message(p.b64decode(ev.content)))
        if info.get('t') != 'pair1':
            raise ValueError('unexpected message')
        check_name(info.get('name'))
        check_relays(info.get('relays'))
        if not isinstance(info.get('epoch'), int) or abs(info['epoch'] - epoch_of(now)) > 1:
            raise ValueError('implausible pairing epoch')
        self.peer = info
        return {'name': info['name'], 'relays': info['relays']}

    def message2(self, rng, now: int) -> Event:
        payload = encode_plaintext({'t': 'pair2', 'name': self.name, 'relays': self.relays}, SIZE_CONTROL)
        ev = rendezvous_event(self.rv_sk, 2, p.b64encode(self.hs.write_message(payload)), self.invite, rng, now)
        self.sas = sas_digits(self.hs.handshake_hash())
        return ev

    def on_message3(self, ev: Event, now: int) -> Contact | None:
        check_rendezvous(ev, self.rv_sk, 3, self.invite, now)
        _, _, k_i2r, k_r2i = self.hs.ss.split()
        body = open_sealed(ev.content, confirm_key(k_i2r))
        if body.get('t') != 'pair3':
            raise ValueError('unexpected message')
        if body.get('ok') is not True:
            return None
        e_p = int(self.peer['epoch'])
        return Contact(self.peer['name'], self.peer['relays'], Direction.from_root(k_r2i, e_p),
                       Direction.from_root(k_i2r, e_p), self.sas)


class Inviter:
    """The party that showed the invite (Noise initiator)."""

    def __init__(self, relays: list, rng, now: int, lifetime: int = 600):
        self.invite = Invite(rng(32), now + lifetime, check_relays(relays))
        self.rv_sk = self.invite.rendezvous_key()
        self.e = rng(32)
        self.commit = None
        self.hs = None
        self.epoch = None
        self.request = None
        self.sas = None

    def rendezvous_pubkey(self) -> str:
        return p.secp_xonly_pub(self.rv_sk).hex()

    def on_commit(self, ev: Event, now: int):
        check_rendezvous(ev, self.rv_sk, 0, self.invite, now)
        if self.commit is not None:
            raise ValueError('invite already used')
        c = p.b64decode(ev.content)
        if len(c) != 32:
            raise ValueError('bad commitment')
        self.commit = c

    def message1(self, name: str, relays: list, rng, now: int) -> Event:
        if self.commit is None or self.hs is not None:
            raise ValueError('out of order')
        self.hs = noise.HandshakeState(NOISE_PATTERN, True, self.invite.prologue(), self.invite.psk, self.e)
        self.epoch = epoch_of(now)
        payload = encode_plaintext({'t': 'pair1', 'name': check_name(name), 'relays': check_relays(relays),
                                    'epoch': self.epoch}, SIZE_CONTROL)
        return rendezvous_event(self.rv_sk, 1, p.b64encode(self.hs.write_message(payload)), self.invite, rng, now)

    def on_message2(self, ev: Event, now: int) -> dict:
        """Returns what to show before the user decides: the joiner's name and the code."""
        check_rendezvous(ev, self.rv_sk, 2, self.invite, now)
        if self.hs is None or self.request is not None:
            raise ValueError('out of order')
        data = p.b64decode(ev.content)
        if not hmac.compare_digest(commitment(data[:noise.DHLEN]), self.commit):
            raise ValueError('commitment mismatch')
        info = decode_plaintext(self.hs.read_message(data))
        if info.get('t') != 'pair2':
            raise ValueError('unexpected message')
        check_name(info.get('name'))
        check_relays(info.get('relays'))
        self.request = info
        self.sas = sas_digits(self.hs.handshake_hash())
        return {'name': info['name'], 'relays': info['relays'], 'sas': self.sas}

    def message3(self, accept: bool, rng, now: int):
        """After the user decision. Returns (event, contact or None)."""
        if self.request is None:
            raise ValueError('out of order')
        _, _, k_i2r, k_r2i = self.hs.ss.split()
        ev = rendezvous_event(self.rv_sk, 3, seal({'t': 'pair3', 'ok': accept}, SIZE_CONTROL, confirm_key(k_i2r), rng),
                              self.invite, rng, now)
        if not accept:
            return ev, None
        contact = Contact(self.request['name'], self.request['relays'], Direction.from_root(k_i2r, self.epoch),
                          Direction.from_root(k_r2i, self.epoch), self.sas)
        return ev, contact


# --- Control channel ----------------------------------------------------------------------
#
# Each direction of a channel has a single addressable slot holding the sender's *current state*
# towards that contact: its home relays and, while it shares with the contact, the stream grant.
# A state without "share" ends any previous grant.

def control_event(contact: Contact, body: dict, rng, now: int) -> Event:
    # Addressable replacement keeps the event with the higher created_at, and on a tie the one with
    # the lower id: created_at must strictly increase per channel or a same-second update may be lost.
    created_at = max(now, contact.last_created_out + 1)
    contact.last_created_out = created_at
    d = contact.outgoing.at(epoch_of(created_at))
    return sign_event(d.signing_key(), created_at, KIND_STORED,
                      [['d', ''], ['expiration', str(epoch_end(d.epoch) + CONTROL_GRACE)]],
                      seal(body, SIZE_CONTROL, d.conversation_key(), rng), rng)


def state_body(seq: int, now: int, relays: list, share: dict | None = None) -> dict:
    body = {'t': 'state', 'seq': seq, 'ts': now, 'relays': check_relays(relays)}
    if share is not None:
        body['share'] = share
    return body


def share_grant(until: int, stream_pk: str, stream_key: bytes) -> dict:
    """`until` is when this recipient's access ends (unix seconds), 0 meaning until stopped."""
    return {'until': until, 'pk': stream_pk, 'key': p.b64encode(stream_key)}


def read_control(contact: Contact, ev: Event, now: int) -> dict | None:
    """Receiver side: decrypt a state event from `contact`, enforcing per-direction sequence order."""
    candidates = incoming_keys(contact, now)
    if not check_event(ev, set(candidates), KIND_STORED, '', now):
        return None
    body = open_sealed(ev.content, candidates[ev.pubkey].conversation_key())
    if body.get('t') != 'state' or not isinstance(body.get('seq'), int):
        return None
    if body['seq'] <= contact.last_seq_in.get('state', 0):
        return None  # replay of an older state, e.g. a grant re-served after it was ended
    check_relays(body.get('relays'))
    contact.last_seq_in['state'] = body['seq']
    return body


# --- Location stream ----------------------------------------------------------------------

@dataclass
class Stream:
    secret: bytes      # signing key (sharer only)
    key: bytes         # NIP-44 conversation key (shared with current recipients)
    seq: int = 0
    last_created: int = 0

    @staticmethod
    def create(rng) -> 'Stream':
        while True:
            sk = rng(32)
            if p.secp_is_valid_secret(sk):
                return Stream(sk, rng(32))

    def pubkey(self) -> str:
        return p.secp_xonly_pub(self.secret).hex()

    def _created_at(self, now: int) -> int:
        # Strictly increasing per stream, see control_event().
        self.last_created = max(now, self.last_created + 1)
        return self.last_created

    def location_event(self, fix: dict, rng, now: int, cap: int | None = None) -> Event:
        self.seq += 1
        body = {'t': 'loc', 'seq': self.seq}
        body.update(fix)
        created_at = self._created_at(now)
        exp = created_at + TTL_LOCATION if cap is None else min(created_at + TTL_LOCATION, cap)
        return sign_event(self.secret, created_at, KIND_STORED, [['d', ''], ['expiration', str(exp)]],
                          seal(body, SIZE_STREAM, self.key, rng), rng)

    def end_event(self, reason: str, rng, now: int) -> Event:
        self.seq += 1
        body = {'t': 'end', 'seq': self.seq, 'ts': now, 'why': reason}
        created_at = self._created_at(now)
        return sign_event(self.secret, created_at, KIND_STORED,
                          [['d', ''], ['expiration', str(created_at + TTL_LOCATION)]],
                          seal(body, SIZE_STREAM, self.key, rng), rng)


def read_stream(grant: dict, ev: Event, last_seq: int, now: int) -> dict | None:
    if not check_event(ev, {grant['pk']}, KIND_STORED, '', now):
        return None
    body = open_sealed(ev.content, p.b64decode(grant['key']))
    if body.get('t') not in ('loc', 'end') or not isinstance(body.get('seq'), int) or body['seq'] <= last_seq:
        return None
    return body


# --- Signals (viewer -> sharer, ephemeral) ------------------------------------------------

def watch_signal(contact: Contact, until: int, rng, now: int) -> Event:
    d = contact.outgoing.at(epoch_of(now))
    return sign_event(d.signing_key(), now, KIND_SIGNAL, [],
                      seal({'t': 'watch', 'ts': now, 'until': until}, SIZE_STREAM, d.conversation_key(), rng), rng)


def incoming_keys(contact: Contact, now: int) -> dict:
    """Receiver's view of a contact's channel towards it, for epochs e-1..e+1 (clock skew)."""
    e = epoch_of(now)
    keys = {}
    for epoch in (e - 1, e, e + 1):
        try:
            d = contact.incoming.at(epoch)
        except ValueError:
            continue  # ratcheted away
        keys[d.pubkey()] = d
    return keys


def read_signal(contact: Contact, ev: Event, now: int) -> dict | None:
    keys = incoming_keys(contact, now)
    if not check_event(ev, set(keys), KIND_SIGNAL, None, now) or ev.created_at < now - 60:
        return None
    body = open_sealed(ev.content, keys[ev.pubkey].conversation_key())
    return body if body.get('t') == 'watch' else None


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
