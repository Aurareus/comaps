"""NLL v1 ("Nostr Live Location") reference implementation.

Normative description: docs/LIVE_LOCATION_PROTOCOL.md. This module mirrors it section by
section and is used to generate the published test vectors. Randomness is injected through
`rng` so that vectors are reproducible.

Python cannot reliably wipe memory, so "erase" below means dropping the last reference. The C++
implementation wipes for real (crypto_wipe).
"""

import hmac
import json
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import nip44, noise, primitives as p
from .nostr import Event

KIND_STORED = 30484      # addressable: pairing messages, control messages, location stream
KIND_SIGNAL = 20484      # ephemeral: viewer -> sharer signals
EPOCH_SECONDS = 86400    # epochs are UTC days
SIZE_CONTROL = 512       # pairing and control plaintexts are space-padded to exactly this size
SIZE_STREAM = 256        # location, stream-end and signal plaintexts are padded to this size
MAX_RELAYS = 4           # relay lists carried in messages
MAX_RELAY_URL = 64       # bytes per relay URL
LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '::1')   # the only hosts allowed with ws:// (local test relays)
MAX_NAME = 64            # bytes
INVITE_VERSION = 1
NOISE_PATTERN = 'NNpsk0'

TTL_LOCATION = 900       # location / stream-end events expire 15 min after creation
CONTROL_GRACE = 3600     # control events expire, and channel keys are erased, 1 h after the end of their epoch
MAX_FUTURE_SKEW = 300    # receivers reject events created more than 5 min in the future
SIGNAL_MAX_AGE = 60      # receivers ignore signals older than this
REKEY_DELAY_MIN = 30     # a replacement stream publishes nothing for a random 30..120 s
REKEY_DELAY_MAX = 120
DECOY_BLOCK = 8          # inbox subscriptions are padded with decoy keys to a multiple of this
MAX_AUTHORS = 50         # authors per REQ filter (nostr-rs-relay times out on 100)


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


def random_below(rng, n: int) -> int:
    """Integer in [0, n) from 32 random bits (the bias, below n / 2^32, is irrelevant for delays and order)."""
    return int.from_bytes(rng(4), 'big') % n


def shuffle(items: list, rng) -> list:
    """Fisher-Yates, in place."""
    for i in range(len(items) - 1, 0, -1):
        j = random_below(rng, i + 1)
        items[i], items[j] = items[j], items[i]
    return items


# --- Plaintext encoding -------------------------------------------------------------------

def encode_plaintext(obj: dict, size: int) -> bytes:
    text = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    if len(text) > size:
        raise ValueError('plaintext too long: %d' % len(text))
    return text + b' ' * (size - len(text))


def check_relay_url(url) -> str:
    """wss:// only; ws:// only to a loopback host (a local test relay)."""
    if not isinstance(url, str) or len(url.encode('utf-8')) > MAX_RELAY_URL:
        raise ValueError('bad relay url')
    if url.startswith('wss://'):
        return url
    if url.startswith('ws://'):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host in LOOPBACK_HOSTS:
            return url
    raise ValueError('bad relay url')


def check_relays(relays) -> list:
    if not isinstance(relays, list) or not 1 <= len(relays) <= MAX_RELAYS:
        raise ValueError('bad relay list')
    for r in relays:
        check_relay_url(r)
    return relays


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
    relays: list           # the peer's home relays (its inbox and stream outbox)
    outgoing: Direction    # me -> peer
    incoming: Direction    # peer -> me
    sas: str
    last_seq_in: dict = field(default_factory=dict)
    seq_out: int = 0       # last state seq sent on the outgoing direction
    last_created_out: int = 0


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
# Four rendezvous events, all kind 30484 signed by the invite's rendezvous key and published to the
# inviter's relays, with d = "0".."3":
#   0  joiner  -> inviter  commitment SHA256(label('commit') || joiner's Noise ephemeral public key)
#   1  inviter -> joiner   Noise NNpsk0 message 1 (psk, e)   payload pair1 (nothing else)
#   2  joiner  -> inviter  Noise NNpsk0 message 2 (e, ee)    payload pair2: name, relays
#   3  inviter -> joiner   NIP-44 under the confirm key      payload pair3: ok, name, relays, epoch
# The inviter is the Noise initiator. The joiner commits to its ephemeral key before it sees the
# inviter's, and each side accepts exactly one event per step, so a man in the middle who knows the
# PSK must fix both of its keys before it learns either code: each code is random to it (match
# probability 1e-6). The code depends only on the keys, so varying a payload cannot change it.

def commitment(e_public: bytes) -> bytes:
    return p.sha256(label('commit') + e_public)


def confirm_key(k1: bytes) -> bytes:
    return p.hkdf_expand(k1, label('pair3'), 32)


def rendezvous_event(rv_sk: bytes, step: int, content: str, invite: Invite, rng, now: int) -> Event:
    return sign_event(rv_sk, now, KIND_STORED, [['d', str(step)], ['expiration', str(invite.expires_at)]], content,
                      rng)


def check_rendezvous(ev: Event, rv_sk: bytes, step: int, invite: Invite, now: int):
    """Envelope check. Failing events can come from anyone and are ignored; passing ones were signed by
    someone who knows the PSK and count for the single-use rule."""
    if now >= invite.expires_at or not check_event(ev, {p.secp_xonly_pub(rv_sk).hex()}, KIND_STORED, str(step), now):
        raise ValueError('bad envelope')


class _SingleUse:
    """Each side accepts exactly one event per step (§6.3). Copies of it from other relays are ignored;
    a different event for an accepted step means that someone else holds the invite."""

    def __init__(self):
        self.accepted = {}

    def first(self, step: int, ev: Event) -> bool:
        prev = self.accepted.get(step)
        if prev is None:
            self.accepted[step] = ev.id
            return True
        if prev == ev.id:
            return False
        raise PairingAborted('a second, different step %d: someone else has this invite' % step)


class Joiner:
    """The party that scanned/opened the invite (Noise responder)."""

    def __init__(self, invite: Invite, name: str, relays: list, rng, now: int):
        if now >= invite.expires_at:
            raise ValueError('invite expired')
        self.invite, self.name, self.relays = invite, check_name(name), check_relays(relays)
        self.e = rng(32)    # used in exactly one step 2, never again
        self.hs = noise.HandshakeState(NOISE_PATTERN, False, invite.prologue(), invite.psk, self.e)
        self.rv_sk = invite.rendezvous_key()
        self.steps = _SingleUse()
        self.step2 = None
        self.k1 = self.k2 = None
        self.sas = None
        self.done = False

    def commit_event(self, rng, now: int) -> Event:
        """Step 0. A retransmission must resend this same event, never a new one."""
        return rendezvous_event(self.rv_sk, 0, p.b64encode(commitment(p.x25519_public(self.e))), self.invite, rng, now)

    def on_message1(self, ev: Event, rng, now: int) -> Event | None:
        """Answers the one step 1 with step 2 (returned, to publish), or returns None for a copy of it."""
        check_rendezvous(ev, self.rv_sk, 1, self.invite, now)
        if self.done or not self.steps.first(1, ev):
            return None
        try:
            info = decode_plaintext(self.hs.read_message(p.b64decode(ev.content)))
        except Exception:
            raise PairingAborted('invalid step 1')
        if info.get('t') != 'pair1':
            raise PairingAborted('invalid step 1')
        payload = encode_plaintext({'t': 'pair2', 'name': self.name, 'relays': self.relays}, SIZE_CONTROL)
        self.step2 = rendezvous_event(self.rv_sk, 2, p.b64encode(self.hs.write_message(payload)), self.invite, rng,
                                      now)
        _, _, self.k1, self.k2 = self.hs.ss.split()
        self.handshake_hash = self.hs.handshake_hash()    # for vectors and debugging only
        self.hs = self.e = None
        self.sas = sas_digits(self.k1)
        return self.step2

    def on_message3(self, ev: Event, now: int) -> 'Contact | None':
        check_rendezvous(ev, self.rv_sk, 3, self.invite, now)
        if self.step2 is None:
            raise ValueError('out of order')   # held until step 2 has been sent (§6.3)
        if self.done or not self.steps.first(3, ev):
            return None
        try:
            body = open_sealed(ev.content, confirm_key(self.k1))
        except Exception:
            raise PairingAborted('invalid step 3')
        if body.get('t') != 'pair3':
            raise PairingAborted('invalid step 3')
        self.done = True
        contact = None
        if body.get('ok') is True:
            e_p = body.get('epoch')
            if not isinstance(e_p, int) or abs(e_p - epoch_of(now)) > 1:
                raise PairingAborted('implausible pairing epoch')
            contact = Contact(check_name(body.get('name')), check_relays(body.get('relays')),
                              Direction.from_root(self.k2, e_p), Direction.from_root(self.k1, e_p), self.sas)
        self.k1 = self.k2 = None    # the roots: whoever holds them can derive every later chain key
        return contact


class Inviter:
    """The party that showed the invite (Noise initiator)."""

    def __init__(self, relays: list, rng, now: int, lifetime: int = 600):
        self.invite = Invite(rng(32), now + lifetime, check_relays(relays))
        self.rv_sk = self.invite.rendezvous_key()
        self.e = rng(32)
        self.steps = _SingleUse()
        self.commit = None
        self.hs = None
        self.request = None
        self.k1 = self.k2 = None
        self.sas = None
        self.decided = False

    def rendezvous_pubkey(self) -> str:
        return p.secp_xonly_pub(self.rv_sk).hex()

    def on_commit(self, ev: Event, rng, now: int) -> Event | None:
        """Takes the one step 0 and answers it with step 1 (returned, to publish)."""
        check_rendezvous(ev, self.rv_sk, 0, self.invite, now)
        if self.decided:
            raise ValueError('invite already used')
        if not self.steps.first(0, ev):
            return None
        c = p.b64decode(ev.content)
        if len(c) != 32:
            raise PairingAborted('invalid step 0')
        self.commit = c
        self.hs = noise.HandshakeState(NOISE_PATTERN, True, self.invite.prologue(), self.invite.psk, self.e)
        payload = encode_plaintext({'t': 'pair1'}, SIZE_CONTROL)
        return rendezvous_event(self.rv_sk, 1, p.b64encode(self.hs.write_message(payload)), self.invite, rng, now)

    def on_message2(self, ev: Event, now: int) -> dict | None:
        """Returns what to show before the user decides: the joiner's name and the code."""
        check_rendezvous(ev, self.rv_sk, 2, self.invite, now)
        if self.hs is None and self.request is None:
            raise ValueError('out of order')   # held until step 1 has been sent (§6.3)
        if self.decided or not self.steps.first(2, ev):
            return None
        data = p.b64decode(ev.content)
        if not hmac.compare_digest(commitment(data[:noise.DHLEN]), self.commit):
            raise PairingAborted('step 2 does not open the commitment')
        try:
            info = decode_plaintext(self.hs.read_message(data))
            if info.get('t') != 'pair2':
                raise ValueError('unexpected message')
            check_name(info.get('name'))
            check_relays(info.get('relays'))
        except Exception:
            raise PairingAborted('invalid step 2')
        _, _, self.k1, self.k2 = self.hs.ss.split()
        self.handshake_hash = self.hs.handshake_hash()    # for vectors and debugging only
        self.hs = self.e = None
        self.request = info
        self.sas = sas_digits(self.k1)
        return {'name': info['name'], 'relays': info['relays'], 'sas': self.sas}

    def message3(self, accept: bool, name: str, relays: list, rng, now: int):
        """After the user's decision. Returns (event, contact or None). The inviter's name, relays and the
        pairing epoch travel here, under a key that needs the ee exchange, rather than in step 1 where
        the PSK alone protects them."""
        if self.request is None or self.decided:
            raise ValueError('out of order')
        self.decided = True
        e_p = epoch_of(now)
        body = {'t': 'pair3', 'ok': True, 'name': check_name(name), 'relays': check_relays(relays), 'epoch': e_p} \
            if accept else {'t': 'pair3', 'ok': False}
        ev = rendezvous_event(self.rv_sk, 3, seal(body, SIZE_CONTROL, confirm_key(self.k1), rng), self.invite, rng,
                              now)
        contact = Contact(self.request['name'], self.request['relays'], Direction.from_root(self.k1, e_p),
                          Direction.from_root(self.k2, e_p), self.sas) if accept else None
        self.k1 = self.k2 = None
        self.invite.psk = None
        return ev, contact


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
    d = contact.outgoing.at(epoch_of(created_at))
    return sign_event(d.signing_key(), created_at, KIND_STORED,
                      [['d', ''], ['expiration', str(epoch_end(d.epoch) + CONTROL_GRACE)]],
                      seal(body, SIZE_CONTROL, d.conversation_key(), rng), rng)


def state_body(seq: int, now: int, relays: list, share: dict | None = None) -> dict:
    body = {'t': 'state', 'seq': seq, 'ts': now, 'relays': check_relays(relays)}
    if share is not None:
        body['share'] = share
    return body


def state_event(contact: Contact, relays: list, share: dict | None, rng, now: int) -> Event:
    contact.seq_out += 1
    return control_event(contact, state_body(contact.seq_out, now, relays, share), rng, now)


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


# --- Subscriptions ------------------------------------------------------------------------

def decoy_keys(decoy_seed: bytes, epoch: int, count: int) -> list:
    """Stable for the whole epoch, so that reconnecting does not reveal which keys are real (§11)."""
    out = []
    for i in range(count):
        prk = p.hkdf_expand(decoy_seed, label('decoy') + epoch.to_bytes(4, 'big') + i.to_bytes(4, 'big'), 32)
        out.append(p.secp_xonly_pub(derive_secp_key(prk, 'decoy-sign')).hex())
    return out


def inbox_filters(contacts: list, decoy_seed: bytes, epoch: int, now: int) -> list:
    """REQ filters for one's own home relays: every contact's channel key of ONE epoch, padded with decoys
    and sorted, for both states and signals. A connection never mixes epochs (§11)."""
    real = [c.incoming.at(epoch).pubkey() for c in contacts]
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


def read_stream(grant: dict, ev: Event, last_seq: int, now: int) -> dict | None:
    if not check_event(ev, {grant['pk']}, KIND_STORED, '', now):
        return None
    body = open_sealed(ev.content, p.b64decode(grant['key']))
    if body.get('t') not in ('loc', 'end') or not isinstance(body.get('seq'), int) or body['seq'] <= last_seq:
        return None
    return body


class Sharer:
    """Sharer side of §9: one stream for all current recipients, replaced whenever anyone is added or
    removed (including by `until`) and at every new epoch. Nothing here is written to disk."""

    def __init__(self, relays: list):
        self.relays = check_relays(relays)
        self.grants = {}         # Contact -> until (0 = until stopped)
        self.stream = None
        self.stream_epoch = None
        self.not_before = 0

    def _states(self, removed: list, rng, now: int) -> list:
        evs = [state_event(c, self.relays, share_grant(u, self.stream.pubkey(), self.stream.key), rng, now)
               for c, u in self.grants.items()]
        evs += [state_event(c, self.relays, None, rng, now) for c in removed]
        return shuffle(evs, rng)

    def start(self, grants: dict, rng, now: int) -> list:
        if self.stream is not None:
            raise ValueError('already sharing')
        self.grants = dict(grants)
        self.stream, self.stream_epoch, self.not_before = Stream.create(rng), epoch_of(now), now
        return self._states([], rng, now)

    def change(self, grants: dict, rng, now: int) -> list:
        """A new recipient set (or the same one at a new epoch). Returns the events to publish now, in this
        order: every state (new grants and share-less ones, shuffled), then the old stream's end. The new
        stream stays silent until `not_before`."""
        if not grants:
            return self.stop(rng, now)
        removed = [c for c in self.grants if c not in grants]
        old = self.stream
        self.grants = dict(grants)
        self.stream, self.stream_epoch = Stream.create(rng), epoch_of(now)
        events = self._states(removed, rng, now) + [old.end_event(rng, now)]
        self.not_before = now + REKEY_DELAY_MIN + random_below(rng, REKEY_DELAY_MAX - REKEY_DELAY_MIN + 1)
        return events

    def extend(self, contact: Contact, until: int, rng, now: int) -> Event:
        """A new `until` for a current recipient: same stream, no re-key."""
        self.grants[contact] = until
        return state_event(contact, self.relays, share_grant(until, self.stream.pubkey(), self.stream.key), rng, now)

    def stop(self, rng, now: int) -> list:
        """Same shape as change() seen from a removed recipient: states (shuffled), then the end."""
        removed = list(self.grants)
        self.grants = {}
        events = self._states(removed, rng, now) + [self.stream.end_event(rng, now)]
        self.stream = None
        return events

    def tick(self, rng, now: int) -> list:
        """Time limits and the epoch change."""
        if self.stream is None:
            return []
        current = {c: u for c, u in self.grants.items() if u == 0 or u > now}
        if len(current) != len(self.grants) or epoch_of(now) != self.stream_epoch:
            return self.change(current, rng, now)
        return []

    def location(self, fix: dict, rng, now: int) -> Event | None:
        if self.stream is None or now < self.not_before:
            return None
        return self.stream.location_event(fix, rng, now)


class Following:
    """Viewer side of one contact's share: the current grant and the latest position, in memory only.
    A replaced or ended stream key is dropped at once (§12)."""

    def __init__(self):
        self.grant = None
        self.last_seq = 0
        self.position = None

    def on_state(self, state: dict, now: int):
        share = state.get('share')
        if share is None or (share['until'] and share['until'] <= now):
            self.stop()
        elif self.grant is None or share['pk'] != self.grant['pk']:
            self.grant, self.last_seq = share, 0     # a new stream; the old position stays until replaced
        else:
            self.grant = share                       # e.g. a new `until`

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
            self.stop()
        else:
            self.position = body
        return body

    def stop(self):
        self.grant, self.last_seq, self.position = None, 0, None


# --- Signals (viewer -> sharer, ephemeral) ------------------------------------------------

def watch_signal(contact: Contact, until: int, rng, now: int) -> Event:
    ratchet(contact, now)
    d = contact.outgoing.at(epoch_of(now))
    return sign_event(d.signing_key(), now, KIND_SIGNAL, [],
                      seal({'t': 'watch', 'ts': now, 'until': until}, SIZE_STREAM, d.conversation_key(), rng), rng)


def read_signal(contact: Contact, ev: Event, now: int) -> dict | None:
    keys = incoming_keys(contact, now)
    if not check_event(ev, set(keys), KIND_SIGNAL, None, now) or ev.created_at < now - SIGNAL_MAX_AGE:
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
