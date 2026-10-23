"""End-to-end scenario tests of the NLL v1 reference implementation (no network)."""

import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nll import nip44, noise, primitives as p, protocol as P  # noqa: E402
from nll.nostr import Event  # noqa: E402

failures = 0
checks = 0


def check(cond, what):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        print('FAIL:', what)


def raises(fn, exc=Exception):
    try:
        fn()
        return False
    except exc:
        return True


rng = P.TestRng(b'scenario')
T0 = 1_760_000_000          # a fixed "now" (2025-10-09T08:53:20Z)
RELAYS_A = ['wss://nos.lol', 'wss://nostr.mom', 'wss://relay.primal.net']
RELAYS_B = ['wss://nos.lol', 'wss://relay.nostr.net']


def wire(ev):
    """Round-trip through JSON, as relays would."""
    return Event.from_dict(json.loads(ev.to_json()))


class Relay:
    """What pairing sees of a relay: addressable events, the newest kept per (pubkey, kind, d) (NIP-01)."""

    def __init__(self):
        self.slots = {}

    def publish(self, ev):
        key = (ev.pubkey, ev.kind, ev.tag_value('d'))
        old = self.slots.get(key)
        if old is None or ev.created_at > old.created_at or (ev.created_at == old.created_at and ev.id < old.id):
            self.slots[key] = ev

    def query(self, authors=None, p_tag=None, now=None):
        """With `now`, expired events are no longer served (NIP-40)."""
        out = [wire(ev) for ev in self.slots.values()
               if (authors is None or ev.pubkey in authors) and (p_tag is None or ev.tag_value('p') == p_tag) and
               (now is None or int(ev.tag_value('expiration')) > now)]
        return sorted(out, key=lambda ev: (ev.created_at, ev.id))


def read_inbox(contact, relay, now):
    """The states from `contact` that an app reading its inbox relay at `now` accepts."""
    events = relay.query(authors=set(P.incoming_keys(contact, now)), now=now)
    return [st for st in (P.read_control(contact, ev, now) for ev in events) if st is not None]


def online(party, relay, now):
    """The party's app is open: it reads its pairing subscriptions and publishes what it is asked to.
    Returns the outcomes; PairingAborted propagates."""
    ipk = party.invite.ipk.hex()
    events = relay.query(p_tag=ipk)
    if isinstance(party, P.Joiner):
        events = sorted(events + relay.query(authors={ipk}), key=lambda ev: (ev.created_at, ev.id))
    outcomes = []
    for ev in events:
        try:
            out = party.on_event(ev, rng, now)
        except ValueError as e:
            if 'out of order' in str(e):
                continue                        # held until due
            raise
        if out is not None:
            outcomes.append(out)
            if out.publish is not None:
                relay.publish(out.publish)
    return outcomes


def joiner_starts(link, name, relay, now):
    joiner = P.Joiner(P.Invite.from_link(link), name, RELAYS_B, rng, now)
    relay.publish(joiner.commit_event(rng, now))
    return joiner


def pair(name_inviter, relays_inviter, name_joiner, relays_joiner, now, checks_on=True):
    relay = Relay()
    inviter = P.Inviter(relays_inviter, rng, now)
    link = inviter.invite.link()
    joiner = P.Joiner(P.Invite.from_link(link), name_joiner, relays_joiner, rng, now + 5)
    m0 = joiner.commit_event(rng, now + 5)
    check(joiner.commit_event(rng, now + 6) is m0, 'step 0 is made once; a retransmission resends it')
    relay.publish(m0)
    online(inviter, relay, now + 6)                                       # step 1
    check(inviter.on_event(wire(m0), rng, now + 6) is None, 'a copy of step 0 from another relay is ignored')
    out = online(joiner, relay, now + 7)                                  # step 2
    check(len(out) == 1 and out[0].show_code['sas'] == joiner.sas, 'joiner shows the code after step 2')
    check(online(joiner, relay, now + 7) == [], 'copies of step 1 are not answered again')
    req = online(inviter, relay, now + 8)[0].show_code
    check(req['name'] == name_joiner and req['sas'] == joiner.sas, 'inviter sees joiner name and the same code')
    done = inviter.decide(True, name_inviter, relays_inviter, rng, now + 20)
    relay.publish(done.publish)
    c_inviter = done.contact
    finished = online(joiner, relay, now + 21)[0]
    c_joiner = finished.contact
    if checks_on:
        check(not c_inviter.confirmed and c_joiner.confirmed, 'the inviter waits for the joiner to confirm')
        check(finished.publish is not None and finished.publish.kind == P.KIND_STORED and
              finished.publish.pubkey == c_joiner.outgoing.at(P.epoch_of(now + 21)).pubkey(),
              'the joiner publishes one state on the new channel when it accepts step 3')
        state = P.read_control(c_inviter, wire(finished.publish), now + 22)
        check(state is not None and 'share' not in state and c_inviter.confirmed,
              'that share-less state confirms the contact on the inviter\'s side')
        check(c_joiner.joiner and not c_inviter.joiner and c_joiner.pairing_epoch == c_inviter.pairing_epoch,
              'both sides know the pairing epoch; only the joiner owes confirmations')
        check(not P.confirmation_due(c_joiner, now + 22) and not P.confirmation_due(c_inviter, now + 22),
              'the first confirmation covers its UTC day')
        check(c_inviter.sas == c_joiner.sas, 'SAS agree')
        check(c_inviter.outgoing.chain_key == c_joiner.incoming.chain_key, 'A->B chain keys agree')
        check(c_inviter.incoming.chain_key == c_joiner.outgoing.chain_key, 'B->A chain keys agree')
        check(c_inviter.outgoing.chain_key != c_inviter.incoming.chain_key, 'directions differ')
        check(c_joiner.name == name_inviter and c_inviter.name == name_joiner, 'names exchanged')
        check(c_joiner.relays == relays_inviter and c_inviter.relays == relays_joiner, 'relays exchanged')
        check(not c_inviter.verified and not c_joiner.verified, 'contacts start unverified')
        for side, key in ((inviter, 'isk'), (joiner, 'jsk')):
            check(None is side.invite.psk is getattr(side, key) is side.e is side.hs is side.k1 is side.k2,
                  '%s erased the PSK, its pairing key, the ephemeral key, the Noise state and the roots' % key[0])
            check(side.mac_key is not None, '%s keeps only the MAC key, to watch until expiry' % key[0])
        check(online(inviter, relay, now + 30) == [] and online(joiner, relay, now + 30) == [],
              'watching after completion: nothing new, nothing flagged')
    return c_inviter, c_joiner, {'relay': relay, 'inviter': inviter, 'joiner': joiner, 'link': link}


def mallory_step1(invite, relay, rng_, now):
    """A link holder's forged step 1: it can encrypt like the inviter, but signs with its own key."""
    msk = P.random_secp_key(rng_)
    hs = noise.HandshakeState(P.NOISE_PATTERN, True, invite.prologue(bytes(32), bytes(32)), invite.psk, rng_(32))
    payload = P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL)
    ev = P.pairing_event(msk, 1, invite, p.b64encode(hs.write_message(payload)), rng_, now)
    relay.publish(ev)
    return ev


# --- Pairing ---------------------------------------------------------------------------------

a_bob, bob_a, ctx = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0)
a_carol, carol_a, _ = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0 + 100)

# The invite carries the inviter's pairing key; intercepted, it lets an eavesdropper decrypt step 1,
# which carries nothing.
relay = Relay()
inv = P.Inviter(RELAYS_A, rng, T0, lifetime=86400)
link = inv.invite.link()
check(len(inv.invite.encode()) == 1 + 32 + 32 + 4 + 1 + sum(1 + len(r) for r in RELAYS_A), 'invite layout')
bob = joiner_starts(link, 'Bob', relay, T0)
step1 = online(inv, relay, T0 + 1)[0].publish
eve = noise.HandshakeState(P.NOISE_PATTERN, False, inv.invite.prologue(bob.jpk, bob.c), inv.invite.psk,
                           os.urandom(32))
check(P.decode_plaintext(eve.read_message(p.b64decode(step1.content))) == {'t': 'pair1'},
      'step 1 reveals nothing to someone holding the invite')

# The review's scenario: Mallory reads Alice's link. Bob publishes step 0 and closes the app, Alice
# answers, Mallory publishes her own step 1. It goes into her own slot (her key), so Alice's step 1 is
# still there, and Bob, back an hour later, ignores Mallory's: only the key in the invite signs step 1.
fake = mallory_step1(P.Invite.from_link(link), relay, rng, T0 + 2)
check(relay.query(authors={inv.invite.ipk.hex()})[0].id == step1.id, "Alice's step 1 cannot be replaced")
out = online(bob, relay, T0 + 3600)
check(len(out) == 1 and out[0].publish is not None, 'Bob answers the real step 1 and ignores the forged one')
online(inv, relay, T0 + 3601)
relay.publish(inv.decide(True, 'Alice', RELAYS_A, rng, T0 + 3602).publish)
c = online(bob, relay, T0 + 3603)[0].contact
check(c is not None and c.sas == inv.sas, 'Bob pairs with the real Alice')
check(bob.on_event(wire(fake), rng, T0 + 3604) is None, 'a forged step 1 is ignored after completion too')

# Mallory as a second joiner while Bob is offline: both apps see both commitments and abort.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0, lifetime=86400)
link = alice.invite.link()
bob = joiner_starts(link, 'Bob', relay, T0)
mallory = joiner_starts(link, 'Bob', relay, T0 + 60)
check(raises(lambda: online(alice, relay, T0 + 120), P.PairingAborted), 'inviter aborts: two joiners used the invite')
check(raises(lambda: online(bob, relay, T0 + 180), P.PairingAborted), 'joiner aborts: another joiner used the invite')
check(alice.mac_key is None and alice.invite.psk is None and bob.mac_key is None and bob.jsk is None,
      'an abort erases everything')

# Mallory first, and Alice connects without comparing codes; Bob opens the link later. Alice's app,
# still watching until the invite expires, flags the contact; Bob's aborts.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0, lifetime=86400)
link = alice.invite.link()
mallory = joiner_starts(link, 'Bob', relay, T0)
online(alice, relay, T0 + 1)
online(mallory, relay, T0 + 2)
online(alice, relay, T0 + 3)
relay.publish(alice.decide(True, 'Alice', RELAYS_A, rng, T0 + 4).publish)
fake_bob = alice.contact
bob = joiner_starts(link, 'Bob', relay, T0 + 3600)
out = online(alice, relay, T0 + 3601)
check(len(out) == 1 and out[0].flagged and fake_bob.flagged, 'after pairing, a second joiner flags the contact')
check(raises(lambda: online(bob, relay, T0 + 3602), P.PairingAborted), 'the late real joiner aborts')
# The same seen from the joiner: after its pairing ended, a later joiner flags the contact.
c_inv, c_join, ctx = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
joiner_starts(ctx['link'], 'Mallory', ctx['relay'], T0 + 40)
check([o.flagged for o in online(ctx['joiner'], ctx['relay'], T0 + 41)] == [True] and c_join.flagged,
      'joiner flags its contact when another joiner shows up later')
check([o.flagged for o in online(ctx['inviter'], ctx['relay'], T0 + 41)] == [True] and c_inv.flagged,
      'inviter flags its contact too')

# Envelope types (§12 item 1). Python serialises the string "d0" exactly like the tag ["d", "0"], so a
# step 0 whose first tag is that string keeps a valid id and signature; a typed parser (the C++ one)
# refuses it, and so must the reference. Likewise uppercase hex, which bytes.fromhex() would accept.
invite_t = P.Inviter(RELAYS_A, rng, T0).invite
joiner_t = P.Joiner(P.Invite.from_link(invite_t.link()), 'Bob', RELAYS_B, rng, T0)
m0_t = joiner_t.commit_event(rng, T0)
check(P.pairing_step(wire(m0_t), invite_t, T0) == 0, 'a well-typed step 0 passes')
odd = wire(m0_t)
odd.tags = ['d0'] + odd.tags[1:]
check(odd.compute_id() == m0_t.id and P.pairing_step(odd, invite_t, T0) is None,
      'a tag given as a string is refused, although its serialisation, id and signature are unchanged')
upper = wire(m0_t)
upper.sig = upper.sig.upper()
check(P.pairing_step(upper, invite_t, T0) is None, 'uppercase hex in a signature is refused')
upper = wire(m0_t)
upper.content = 5
check(P.pairing_step(upper, invite_t, T0) is None, 'content that is not a string is refused')

# Without the PSK nothing counts: a step 0 with a wrong MAC is ignored by both sides (no denial of
# service by someone who merely sees the inviter's key on a relay).
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
link = alice.invite.link()
bob = joiner_starts(link, 'Bob', relay, T0)
junk = P.Joiner(P.Invite(os.urandom(32), alice.invite.ipk, alice.invite.expires_at, RELAYS_A), 'X', RELAYS_B, rng,
                T0)
relay.publish(junk.commit_event(rng, T0))
check(len(online(alice, relay, T0 + 1)) == 1, 'inviter ignores a step 0 without proof of the PSK')
check(len(online(bob, relay, T0 + 2)) == 1, 'joiner ignores it too')

# A step 1 from the inviter that answers another joiner's step 0 cannot be decrypted (the prologue
# binds the accepted step 0): the joiner aborts without revealing its key.
alice = P.Inviter(RELAYS_A, rng, T0)
link = alice.invite.link()
m, b = (P.Joiner(P.Invite.from_link(link), n, RELAYS_B, rng, T0) for n in ('M', 'B'))
s1 = alice.on_event(wire(m.commit_event(rng, T0)), rng, T0).publish
check(raises(lambda: b.on_event(wire(s1), rng, T0), P.PairingAborted) and b.step2 is None,
      'joiner aborts on a step 1 meant for someone else, and sends no step 2')

# Declining: the joiner learns it and gets no contact.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
dave = joiner_starts(alice.invite.link(), 'Dave', relay, T0)
online(alice, relay, T0)
online(dave, relay, T0)
online(alice, relay, T0)
d = alice.decide(False, 'Alice', RELAYS_A, rng, T0)
relay.publish(d.publish)
check(d.contact is None and d.declined and [o.declined for o in online(dave, relay, T0)] == [True],
      'decline: no contact on either side')

# A low-order Noise key gives an all-zero ee. PyCA refuses it and Monocypher returns zeros; both must
# abort. Here a link holder commits to a low-order point and builds step 2 with ee = 0, as an unchecked
# X25519 would accept.
LOW_ORDER = bytes.fromhex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800')
alice = P.Inviter(RELAYS_A, rng, T0)
inv_m = P.Invite.from_link(alice.invite.link())
msk = P.random_secp_key(rng)
mpk = p.secp_xonly_pub(msk)
c_low = P.commitment(LOW_ORDER)
s0 = P.pairing_event(msk, 0, inv_m, P.step0_content(inv_m.mac_key(), mpk, c_low), rng, T0)
s1 = alice.on_event(wire(s0), rng, T0).publish
hs = noise.HandshakeState(P.NOISE_PATTERN, False, inv_m.prologue(mpk, c_low), inv_m.psk, os.urandom(32))
hs.read_message(p.b64decode(s1.content))
hs.ss.mix_hash(LOW_ORDER)
hs.ss.mix_key(LOW_ORDER)
hs.ss.mix_key(bytes(32))
msg2 = LOW_ORDER + hs.ss.encrypt_and_hash(P.encode_plaintext({'t': 'pair2', 'name': 'M', 'relays': RELAYS_B},
                                                             P.SIZE_CONTROL))
s2 = P.pairing_event(msk, 2, inv_m, p.b64encode(msg2), rng, T0)
check(raises(lambda: alice.on_event(wire(s2), rng, T0), P.PairingAborted), 'all-zero ee aborts the pairing')
# The same on the joiner's side: a step 1 (only the real inviter can sign one) whose ephemeral key is a
# low-order point. Writing step 2 computes ee; that must abort the pairing, not escape as a plain error.
alice = P.Inviter(RELAYS_A, rng, T0)
bob = P.Joiner(P.Invite.from_link(alice.invite.link()), 'Bob', RELAYS_B, rng, T0)
hs = noise.HandshakeState(P.NOISE_PATTERN, True, alice.invite.prologue(bob.jpk, bob.c), alice.invite.psk,
                          os.urandom(32))
hs.ss.mix_key_and_hash(alice.invite.psk)
hs.ss.mix_hash(LOW_ORDER)
hs.ss.mix_key(LOW_ORDER)
msg1 = LOW_ORDER + hs.ss.encrypt_and_hash(P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL))
s1 = P.pairing_event(alice.isk, 1, alice.invite, p.b64encode(msg1), rng, T0)
check(raises(lambda: bob.on_event(wire(s1), rng, T0), P.PairingAborted) and bob.step2 is None and
      None is bob.jsk is bob.mac_key is bob.invite.psk, 'joiner aborts on a low-order key in step 1, sends no step 2')

# The code depends only on the keys. Same PSK and ephemeral keys, different step 2 payloads (here
# the joiner's name): the handshake hash differs, the code does not. With a code taken from the
# hash, a man in the middle could vary the step 2 payload it sends to the inviter until the
# inviter's code equals the joiner's (~1e6 cheap tries); taken from the keys, it has nothing to vary.
psk, e_i, e_r = os.urandom(32), os.urandom(32), os.urandom(32)
prologue = P.Inviter(RELAYS_A, rng, T0).invite.prologue(bytes(32), bytes(32))
codes, hashes = set(), set()
for name in ('Bob', 'Bob ', 'Bob  ', 'Robert'):
    i = noise.HandshakeState(P.NOISE_PATTERN, True, prologue, psk, e_i)
    r = noise.HandshakeState(P.NOISE_PATTERN, False, prologue, psk, e_r)
    r.read_message(i.write_message(P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL)))
    i.read_message(r.write_message(P.encode_plaintext({'t': 'pair2', 'name': name, 'relays': RELAYS_B},
                                                      P.SIZE_CONTROL)))
    hashes.add(i.handshake_hash())
    codes.add(P.sas_digits(i.ss.split()[2]))
check(len(hashes) == 4 and len(codes) == 1, 'code independent of payloads (handshake hash is not)')

# A link rewritten in transit (Mallory's own invite) gives a full man in the middle: the protocol
# cannot see it, the codes differ, and the contacts stay unverified until the users compare them.
alice = P.Inviter(RELAYS_A, rng, T0)
mallory_inv = P.Inviter(RELAYS_A, rng, T0)
bob = P.Joiner(P.Invite.from_link(mallory_inv.invite.link()), 'Bob', RELAYS_B, rng, T0)
mallory_j = P.Joiner(P.Invite.from_link(alice.invite.link()), 'Bob', RELAYS_B, rng, T0)
mallory_j.on_event(wire(alice.on_event(wire(mallory_j.commit_event(rng, T0)), rng, T0).publish), rng, T0)
bob.on_event(wire(mallory_inv.on_event(wire(bob.commit_event(rng, T0)), rng, T0).publish), rng, T0)
alice_code = alice.on_event(wire(mallory_j.step2), rng, T0).show_code['sas']
check(alice_code != bob.sas, 'man in the middle with a rewritten link: the two screens show different codes')

# Midnight: the inviter's clock is 4 minutes ahead and it is already the next day there. e_p lags by
# the accepted skew, so it is never in the joiner's future, and every channel operation works.
midnight = P.epoch_end(P.epoch_of(T0))
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, midnight + 60)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, midnight - 180)
online(alice, relay, midnight + 61)
online(bob, relay, midnight - 179)
online(alice, relay, midnight + 62)
relay.publish(alice.decide(True, 'Alice', RELAYS_A, rng, midnight + 63).publish)
c = online(bob, relay, midnight - 177)[0].contact
check(c.incoming.epoch == P.epoch_of(midnight - 177), 'pairing epoch not in the joiner\'s future')
check(P.inbox_filters([c], os.urandom(32), P.epoch_of(midnight - 170), midnight - 170) != [] and
      P.state_event(c, RELAYS_B, None, rng, midnight - 170) is not None and
      P.watch_signal(c, midnight, rng, midnight - 170) is not None,
      'subscriptions, states and signals work right after pairing near midnight')
# A step 3 whose epoch lies in the joiner's future is refused (as an earlier inviter would have sent it).
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, T0)
online(alice, relay, T0)
online(bob, relay, T0)
online(alice, relay, T0)
future = {'t': 'pair3', 'ok': True, 'name': 'Alice', 'relays': RELAYS_A, 'epoch': P.epoch_of(T0) + 1}
relay.publish(P.pairing_event(alice.isk, 3, alice.invite, P.seal(future, P.SIZE_CONTROL, P.confirm_key(alice.k1), rng),
                              rng, T0 + 1))
check(raises(lambda: online(bob, relay, T0 + 1), P.PairingAborted), 'joiner refuses a pairing epoch in its future')
# A contact whose chain is ahead of the clock (the clock was set back) no longer breaks the others.
ahead = P.Contact('x', RELAYS_A, P.Direction(P.epoch_of(T0) + 5, os.urandom(32)),
                  P.Direction(P.epoch_of(T0) + 5, os.urandom(32)), '')
f = P.inbox_filters([ahead, a_bob], os.urandom(32), P.epoch_of(T0), T0)
check(a_bob.incoming.at(P.epoch_of(T0)).pubkey() in f[0]['authors'] and len(f[0]['authors']) == 8,
      'one contact ahead of the clock does not take down the inbox subscription')
check(P.state_event(ahead, RELAYS_A, None, rng, T0) is not None, 'a chain ahead of the clock still signs')

# Expired invite.
check(raises(lambda: P.Joiner(P.Invite.from_link(link), 'Late', RELAYS_B, rng, T0 + 86400 * 2)),
      'expired invite refused')

# Invites live at most a day: the inviter chooses the relays the joiner watches until expiry, so a
# longer life would let it keep a joiner's phone connecting to its relay (and learn its IP) for years.
check(raises(lambda: P.Inviter(['wss://stalker-relay.example'], rng, T0, lifetime=10 * 365 * 86400)),
      'an inviter cannot make an invite that lives over a day')
long = P.Invite(os.urandom(32), alice.invite.ipk, T0 + 10 * 365 * 86400, ['wss://stalker-relay.example'])
check(raises(lambda: P.Joiner(P.Invite.from_link(long.link()), 'Victim', RELAYS_B, rng, T0)),
      'a joiner refuses an invite that expires more than a day ahead')
edge = P.Invite(os.urandom(32), alice.invite.ipk, T0 + P.MAX_INVITE_LIFETIME + P.MAX_FUTURE_SKEW, RELAYS_A)
check(not raises(lambda: P.Joiner(P.Invite.from_link(edge.link()), 'B', RELAYS_B, rng, T0)),
      'a day plus the accepted clock skew is still fine')

# Relay consent: only the user's own relays, the defaults and relays approved earlier are used without
# asking; anything else a contact names needs the user's approval first.
own = set(RELAYS_B)
trusted = own | set(P.DEFAULT_RELAYS)
check(P.split_relays(['wss://nos.lol', 'wss://stalker-relay.example', 'wss://relay.nostr.net'], trusted) ==
      (['wss://nos.lol', 'wss://relay.nostr.net'], ['wss://stalker-relay.example']),
      'relays outside own, default and approved ones need asking')
check(P.split_relays(['wss://stalker-relay.example'], trusted | {'wss://stalker-relay.example'}) ==
      (['wss://stalker-relay.example'], []), 'an approved relay is used without asking again')

# Two-sided completion. Alice decides near the end of the invite's life, and Bob opens CoMaps only after
# it expired: step 3 has expired with the invite, Bob never completes, and Alice's contact stays
# unconfirmed (the app shows "Waiting for Bob", and offers to remove it once the week is over).
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0, lifetime=86400)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, T0)
online(alice, relay, T0 + 1)
online(bob, relay, T0 + 2)
online(alice, relay, T0 + 3)
end = alice.invite.expires_at
relay.publish(alice.decide(True, 'Alice', RELAYS_A, rng, end - 60).publish)
check(online(bob, relay, end + 600) == [] and bob.contact is None and not alice.contact.confirmed,
      'joiner back after expiry: no contact on its side, the inviter\'s stays unconfirmed')
week_over = P.epoch_end(alice.contact.pairing_epoch + P.CONFIRM_EPOCHS) + P.CONTROL_GRACE
check(not P.offer_removal(alice.contact, week_over - 1) and P.offer_removal(alice.contact, week_over),
      'removal is offered once the week is over, not before')
check(raises(lambda: alice.decide(True, 'Alice', RELAYS_A, rng, end + 5)), 'decide() twice refused')
# decide() after expiry: refused, since relays would refuse the step 3 and the joiner has stopped.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, T0)
online(alice, relay, T0 + 1)
online(bob, relay, T0 + 2)
online(alice, relay, T0 + 3)
check(raises(lambda: alice.decide(True, 'Alice', RELAYS_A, rng, alice.invite.expires_at)),
      'decide() refused once the invite has expired')
# Bob taps "They differ" (his app aborts): he never confirms, so Alice's contact stays unconfirmed.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, T0)
online(alice, relay, T0 + 1)
online(bob, relay, T0 + 2)
online(alice, relay, T0 + 3)
bob.abort()
relay.publish(alice.decide(True, 'Alice', RELAYS_A, rng, T0 + 4).publish)
check(online(bob, relay, T0 + 5) == [] and not alice.contact.confirmed,
      '"They differ" on the joiner: no confirmation, the inviter\'s contact stays unconfirmed')
check(bob.commit_event(rng, T0 + 6) is bob.step0, 'an aborted joiner can still resend its old step 0, nothing new')
fresh = P.Joiner(P.Invite.from_link(P.Inviter(RELAYS_A, rng, T0).invite.link()), 'B', RELAYS_B, rng, T0 + 6)
fresh.abort()
check(raises(lambda: fresh.commit_event(rng, T0 + 6), ValueError), 'a joiner aborted before step 0 makes none')
# decide() after an abort is refused too.
relay = Relay()
alice = P.Inviter(RELAYS_A, rng, T0)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, T0)
online(alice, relay, T0 + 1)
online(bob, relay, T0 + 2)
online(alice, relay, T0 + 3)
alice.abort()
check(raises(lambda: alice.decide(True, 'Alice', RELAYS_A, rng, T0 + 4)), 'decide() refused after an abort')

# The confirmation can expire before the inviter reads it. The review's scenario: Bob accepts step 3 at
# 23:30 UTC, his confirmation expires at 01:00, and Alice's app, next opened at 08:00, finds nothing. Bob's
# app sends its current state again on each later UTC day it runs, through epoch e_p + 7.
day = P.epoch_of(T0) + 10
t2330 = P.epoch_end(day) - 1800
relay, inbox_a = Relay(), Relay()                   # the invite's relay and Alice's inbox relay
alice = P.Inviter(RELAYS_A, rng, t2330 - 600, lifetime=3600)
bob = joiner_starts(alice.invite.link(), 'Bob', relay, t2330 - 600)
online(alice, relay, t2330 - 590)
online(bob, relay, t2330 - 580)
online(alice, relay, t2330 - 570)
relay.publish(alice.decide(True, 'Alice', RELAYS_A, rng, t2330 - 60).publish)
finished = online(bob, relay, t2330)[0]
inbox_a.publish(finished.publish)
a_b, b_a = alice.contact, finished.contact
check(b_a.pairing_epoch == day and int(finished.publish.tag_value('expiration')) == t2330 + 5400,
      'a confirmation sent at 23:30 is readable for 1.5 h')
t = P.epoch_end(day) + 8 * 3600                     # 08:00 the next day
check(read_inbox(a_b, inbox_a, t) == [] and not a_b.confirmed, 'Alice at 08:00: nothing to read, Bob still waiting')
check(not P.offer_removal(a_b, t), '"waiting" is a label: no removal offered during the week')
t = P.epoch_end(day) + 12 * 3600                    # Bob's app runs at 12:00
check(P.confirmation_due(b_a, t), 'on a later UTC day the joiner confirms again')
inbox_a.publish(P.Sharer(RELAYS_B).current_state(b_a, rng, t))
check(not P.confirmation_due(b_a, t + 60), 'once per UTC day')
states = read_inbox(a_b, inbox_a, t + 3600)        # Alice at 13:00
check(len(states) == 1 and 'share' not in states[0] and a_b.confirmed, 'Alice reads it at 13:00: Bob is confirmed')
sent = []
for e in range(day + 2, day + 12):
    t = e * P.EPOCH_SECONDS + 7200
    if P.confirmation_due(b_a, t):
        P.Sharer(RELAYS_B).current_state(b_a, rng, t)
        sent.append(e)
check(sent == list(range(day + 2, day + P.CONFIRM_EPOCHS + 1)), 'daily through epoch e_p + 7, then never again')
check(not P.offer_removal(a_b, P.epoch_end(day + 30)), 'a confirmed contact is never offered for removal')

# Waiting does not block sharing, and any message from the joiner confirms, a watch signal included. Bob's
# confirmation is lost here; Alice shares with him anyway, and his first watch signal confirms him.
a_b, b_a, _ = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
t = T0 + 600
view = P.Following()
for ev in P.Sharer(RELAYS_A).start({a_b: 0}, rng, t).states:
    view.on_state(P.read_control(b_a, wire(ev), t + 1), t + 1)
check(not a_b.confirmed and view.grant is not None, 'Alice can share with a waiting contact, and Bob receives it')
check(P.read_signal(a_b, wire(P.watch_signal(b_a, t + 120, rng, t + 2)), t + 3) is not None and a_b.confirmed,
      "Bob's watch signal confirms him")

# The daily confirmation is the joiner's CURRENT state. While Bob shares with Alice it carries his grant: a
# state without `share` would end his share.
a_b, b_a, _ = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
e_p = b_a.pairing_epoch
t = P.epoch_end(e_p) + 600
bob_sh, alice_view = P.Sharer(RELAYS_B), P.Following()
for ev in bob_sh.start({b_a: 0}, rng, t).states:
    alice_view.on_state(P.read_control(a_b, wire(ev), t), t)
check(a_b.confirmed and not P.confirmation_due(b_a, t + 60), "a share's states count as the day's confirmation")
t = P.epoch_end(e_p + 1) + 30
check(bob_sh.tick(rng, t) is not None and not P.confirmation_due(b_a, t + 1),
      'so does the re-key at the new epoch')
t = P.epoch_end(e_p + 2) + 30                       # the check comes before the day's re-key
check(P.confirmation_due(b_a, t), 'a confirmation is due before the re-key')
st = P.read_control(a_b, wire(bob_sh.current_state(b_a, rng, t)), t)
alice_view.on_state(st, t)
check(st.get('share') is not None and st['share']['pk'] == bob_sh.stream.pubkey() and alice_view.grant == st['share'],
      'it carries the current grant, so Alice keeps following')

# Removal is offered exactly when the latest confirmation the joiner can owe has expired.
a_b, b_a, _ = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
week_over = P.epoch_end(a_b.pairing_epoch + P.CONFIRM_EPOCHS) + P.CONTROL_GRACE
last = P.Sharer(RELAYS_B).current_state(b_a, rng, P.epoch_end(b_a.pairing_epoch + P.CONFIRM_EPOCHS) - 1)
check(int(last.tag_value('expiration')) == week_over and not P.offer_removal(a_b, week_over - 1) and
      P.offer_removal(a_b, week_over), 'removal offered from the expiry of the last owed confirmation on')
check(P.read_control(a_b, wire(last), week_over - 1) is not None and not P.offer_removal(a_b, week_over),
      'read in its last second, that confirmation still counts')

# Relays: wss:// only; ws:// only to a loopback host.
for url in ('wss://nos.lol', 'ws://127.0.0.1:7777', 'ws://localhost', 'ws://[::1]:7777/'):
    check(P.check_relays([url]) == [url], 'relay url accepted: ' + url)
for url in ('ws://nos.lol', 'ws://192.168.1.2:7777', 'ws://127.0.0.1.example.com', 'ws://localhost@evil.example',
            'http://nos.lol', 'wss://' + 'x' * 60, 'wss://', 'wss://nos .lol', 'wss://nös.lol', 'wss://nos.lol/"',
            'wss://nos.lol\\', 'ws://localhost/"'):
    check(raises(lambda: P.check_relays([url])), 'relay url refused: ' + url)
check(P.check_name('"' * P.MAX_NAME) and P.check_name('Zoë'), 'names: quotes and letters')
for name in ('', 'Al\tice', 'Alice\n', '\x7f', 'a' * (P.MAX_NAME + 1)):
    check(raises(lambda: P.check_name(name)), 'name refused: %r' % name)

# The largest messages this version sends fit their padded size (spec §5).
longest = ['wss://' + 'a' * (P.MAX_RELAY_URL - 7) + c for c in '1234']
time10, big = 9_999_999_999, 2 ** 53 - 1
long_float = -1.2345678901234567e-300
largest = [(P.state_body(big, time10, longest, {'until': time10, 'pk': 'f' * 64, 'key': 'A' * 43 + '='}, 'deeppurple'),
            P.SIZE_CONTROL),
           ({'t': 'pair3', 'ok': True, 'name': '"' * P.MAX_NAME, 'relays': longest, 'epoch': big}, P.SIZE_CONTROL),
           ({'t': 'pair2', 'name': '"' * P.MAX_NAME, 'relays': longest}, P.SIZE_CONTROL),
           ({'t': 'loc', 'seq': big, 'ts': big, 'lat': long_float, 'lon': long_float, 'acc': long_float,
             'spd': long_float, 'brg': long_float, 'alt': long_float, 'low': True}, P.SIZE_STREAM)]
check(all(len(P.encode_plaintext(body, size)) == size for body, size in largest),
      'the largest state, pair3, pair2 and location fit their size')
plain = P.Invite(os.urandom(32), alice.invite.ipk, T0 + 600, ['wss://nos.lol'])
plain.relays = ['ws://nos.lol']
check(raises(lambda: P.Invite.from_link(plain.link())), 'invite with a ws:// relay refused')
check(raises(lambda: P.Invite.from_link(P.Invite(os.urandom(32), bytes(32), T0, RELAYS_A).link())),
      'invite whose pairing key is not a curve point refused')
check(raises(lambda: p.b64url_nopad_decode('AB')) and p.b64url_nopad_decode('AA') == b'\x00',
      'base64url: unused bits must be zero (canonical)')
check(raises(lambda: p.b64decode('AB==')) and raises(lambda: p.b64decode('AA')) and p.b64decode('AA==') == b'\x00',
      'base64: canonical with padding only')
short = P.Invite(os.urandom(32), alice.invite.ipk, T0 + 600, ['wss://ab.io'])  # 82 bytes: 4 unused bits at the end
tail = short.link()[-1]
check(len(short.encode()) % 3 == 1 and raises(lambda: P.Invite.from_link(short.link()[:-1] + chr(ord(tail) + 1))) and
      P.Invite.from_link(short.link()).relays == ['wss://ab.io'], 'non-canonical base64url in an invite refused')

# --- Sharing ---------------------------------------------------------------------------------


def deliver(events, views, t):
    for ev in events:
        for contact, view in views.items():
            st = P.read_control(contact, wire(ev), t)
            if st is not None:
                view.on_state(st, t)


now = T0 + 200
alice_share = P.Sharer(RELAYS_A)
start = alice_share.start({a_bob: now + 3600, a_carol: 0}, rng, now)
evs = start.states
check(len(evs) == 2 and start.end is None and all(e.kind == P.KIND_STORED for e in evs),
      'start: one state per recipient, no end')
bob_view, carol_view = P.Following(), P.Following()
deliver(evs, {bob_a: bob_view, carol_a: carol_view}, now + 1)
stream = alice_share.stream
check(bob_view.grant['until'] == now + 3600 and bob_view.grant['pk'] == stream.pubkey(), 'bob reads grant')
check(carol_view.grant['until'] == 0 and carol_view.grant['pk'] == stream.pubkey(), 'carol reads grant')
g_bob = next(e for e in evs if e.pubkey == a_bob.outgoing.at(P.epoch_of(now)).pubkey())
check(P.read_control(carol_a, g_bob, now + 1) is None, 'carol cannot read bob grant')
check(P.read_control(bob_a, g_bob, now + 2) is None, 'replayed grant rejected (seq)')

fix = {'ts': now * 1000, 'lat': 52.5200066, 'lon': 13.404954, 'acc': 8.0, 'spd': 1.4, 'brg': 271.0}
loc1 = alice_share.location(fix, rng, now + 5)
check(loc1 is not None, 'a new share publishes at once')
check(int(loc1.tag_value('expiration')) == loc1.created_at + P.TTL_LOCATION,
      'location expiry is created_at + 900, never capped by a recipient time limit')
check(len(loc1.content) == 432, 'location content has constant length (432 chars)')
check(len(g_bob.content) == 772, 'control content has constant length (772 chars)')
check(len(P.state_event(a_bob, RELAYS_A, None, rng, now).content) == 772,
      'control end has the same length as a grant')
r1 = bob_view.on_stream(wire(loc1), now + 6)
check(r1 and r1['lat'] == 52.5200066 and r1['seq'] == 1 and bob_view.position == r1, 'bob reads location')
check(carol_view.on_stream(wire(loc1), now + 6) is not None, 'carol reads location')
check(bob_view.on_stream(wire(loc1), now + 6) is None, 'location replay rejected (seq)')

# Tampering: flip a ciphertext byte -> MAC failure; resign so the envelope is valid. Discarded, not raised.
raw = bytearray(p.b64decode(loc1.content))
raw[40] ^= 1
tampered = P.sign_event(stream.secret, loc1.created_at, loc1.kind, loc1.tags, p.b64encode(bytes(raw)), rng)
check(P.read_stream(bob_view.grant, tampered, 0, now + 6) is None, 'tampered ciphertext discarded silently')
# A recipient forging a location under its own key is rejected (pubkey must be the stream key).
forger = P.Stream(P.random_secp_key(rng), stream.key)
check(P.read_stream(bob_view.grant, forger.location_event(fix, rng, now + 7), 0, now + 7) is None,
      'recipient cannot forge sharer locations')
# Expired events are ignored.
check(P.read_stream(bob_view.grant, loc1, 0, now + 5 + P.TTL_LOCATION) is None, 'expired location ignored')

# Adding someone goes through change(): extend() only moves a current recipient's time limit. A
# newcomer added with extend() would read the latest position, published before its grant.
dave_c, dave_v = pair('Alice', RELAYS_A, 'Dave', RELAYS_B, T0, checks_on=False)[:2]
check(raises(lambda: alice_share.extend(dave_c, 0, rng, now + 8)), 'extend() refuses a new recipient')
check(raises(lambda: alice_share.extend(a_bob, now, rng, now + 8)), 'extend() refuses a time limit in the past')
g = alice_share.extend(a_bob, now + 7200, rng, now + 8)
bob_view.on_state(P.read_control(bob_a, wire(g), now + 9), now + 9)
check(bob_view.grant['until'] == now + 7200 and alice_share.stream is stream, 'extend(): same stream, later until')

# A restart: the stored contact keeps the last seq, not the grant, which was kept in memory only (stream keys
# are never stored). The latest state is read once more, and only it; an older one stays a replay (§8).
check(P.read_control(bob_a, wire(g), now + 10) is None, 'the latest state read again in the same run: a replay')
bob_restarted = dataclasses.replace(bob_a, last_seq_in=dict(bob_a.last_seq_in), last_state_read=False)
check(P.read_control(bob_restarted, g_bob, now + 11) is None, 'after a restart, an older state stays a replay')
st = P.read_control(bob_restarted, wire(g), now + 12)
check(st is not None and st['share']['until'] == now + 7200, 'after a restart, the latest state is read once more')
check(P.read_control(bob_restarted, wire(g), now + 13) is None, 'once')

# --- Revocation: what a removed recipient sees must not depend on whether the share goes on ---


def revocation(remove_only_carol: bool):
    """Alice shares with Bob and Carol, then either removes Carol or stops sharing altogether. Returns what
    anyone watching the relays sees, and what Carol can decrypt if she keeps the old stream key."""
    a_b, b_a, _ = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
    a_c, c_a, _ = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0, checks_on=False)
    t = T0 + 300
    sh = P.Sharer(RELAYS_A)
    bob, carol = P.Following(), P.Following()
    deliver(sh.start({a_b: 0, a_c: 0}, rng, t).states, {b_a: bob, c_a: carol}, t)
    first = wire(sh.location(fix, rng, t + 1))
    bob.on_stream(first, t + 1)
    carol.on_stream(first, t + 1)
    old_pk, carol_key = carol.grant['pk'], carol.grant['key']
    t += 60
    rk = sh.change({a_b: 0}, rng, t) if remove_only_carol else sh.stop(rng, t)
    published = rk.states + [rk.end]
    observed = [(ev.kind, len(ev.content), [tag[0] for tag in ev.tags], ev.tag_value('d'), ev.pubkey == old_pk)
                for ev in published]
    carol_reads = []
    for ev in published:
        st = P.read_control(c_a, wire(ev), t)
        if st is not None:
            carol_reads.append(('state', sorted(st)))
            carol.on_state(st, t)
        elif ev.pubkey == old_pk:      # a Carol who kept the old stream key
            carol_reads.append(('end', sorted(P.open_sealed(ev.content, p.b64decode(carol_key)))))
    return observed, carol_reads, {'sharer': sh, 'bob': bob, 'b_a': b_a, 'carol': carol, 'carol_key': carol_key,
                                   'rekey': rk, 't': t}


seen_remove, carol_remove, ctx = revocation(True)
seen_stop, carol_stop, _ = revocation(False)
check(seen_remove == seen_stop, 'relays see the same events for "remove Carol" and "stop sharing"')
check(carol_remove == carol_stop == [('state', ['relays', 'seq', 't', 'ts']), ('end', ['seq', 't', 'ts'])],
      'Carol decrypts the same messages in both cases: a share-less state and a reason-less end')
check(seen_remove[-1][4] and not any(o[4] for o in seen_remove[:-1]), 'states first, then the old stream\'s end')
check(ctx['carol'].grant is None and ctx['carol'].position is None, 'removed viewer erased key and position')
sh, bob, t = ctx['sharer'], ctx['bob'], ctx['t']
check(P.REKEY_DELAY_MIN <= sh.not_before - t <= P.REKEY_DELAY_MAX, 'new stream delayed by 30..120 s')
check(sh.location(fix, rng, sh.not_before - 1) is None, 'new stream silent before the delay')
# States and the end travel over different relays: here the end reaches Bob first. He keeps the last
# position, marked stale, switches on the grant and is current again with the new stream's first fix.
pos = bob.position
check(bob.on_stream(wire(ctx['rekey'].end), t) is not None and bob.grant is None and bob.position == pos and
      bob.stale, 'end before the grant: Bob erases the stream key but keeps the position, stale')
deliver(ctx['rekey'].states, {ctx['b_a']: bob}, t + 1)
check(bob.grant['pk'] == sh.stream.pubkey() and bob.position == pos and bob.stale,
      'the grant arrives: Bob follows the new stream and still shows the stale position')
bob.tick(t + P.END_GRACE + 60)
check(bob.position == pos, 'with a current grant, the stale position stays until the new stream speaks')
loc2 = wire(sh.location(fix, rng, sh.not_before))
check(bob.on_stream(loc2, sh.not_before) is not None and not bob.stale, 'Bob is current again with the new stream')
check(raises(lambda: P.open_sealed(loc2.content, p.b64decode(ctx['carol_key']))),
      'Carol cannot decrypt the new stream with the old key')
# Stop, with the end first: stale until the share-less state, which removes the dot.
_, _, ctx2 = revocation(False)
bob2 = P.Following()
bob2.grant, bob2.position = {'pk': ctx2['rekey'].end.pubkey, 'key': ctx2['carol_key'], 'until': 0}, {'lat': 1}
bob2.on_stream(wire(ctx2['rekey'].end), ctx2['t'])
check(bob2.stale and bob2.position is not None, 'stop, end first: position kept, stale')
deliver(ctx2['rekey'].states, {ctx2['b_a']: bob2}, ctx2['t'] + 1)
check(bob2.position is None and bob2.grant is None, 'the share-less state then removes it')
# An end with nothing after it: the stale position goes after END_GRACE.
bob3 = P.Following()
bob3.grant, bob3.position = {'pk': ctx2['rekey'].end.pubkey, 'key': ctx2['carol_key'], 'until': 0}, {'lat': 1}
bob3.on_stream(wire(ctx2['rekey'].end), ctx2['t'])
bob3.tick(ctx2['t'] + P.END_GRACE - 1)
check(bob3.position is not None, 'kept during the grace period')
bob3.tick(ctx2['t'] + P.END_GRACE)
check(bob3.position is None, 'dropped when the grace period is over')

# Time limits end on time: Carol's `until` passes and she is removed exactly as above.
a_b, b_a, _ = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0, checks_on=False)
a_c, c_a, _ = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0, checks_on=False)
t = T0 + 300
sh = P.Sharer(RELAYS_A)
carol = P.Following()
deliver(sh.start({a_b: 0, a_c: t + 600}, rng, t).states, {c_a: carol}, t)
check(sh.tick(rng, t + 599) is None, 'nothing changes before the time limit')
check(carol.on_stream(wire(sh.location(fix, rng, t + 599)), t + 600) is None and carol.grant is None,
      'the viewer enforces until locally as well')
expired = sh.tick(rng, t + 600)
check([(e.kind, len(e.content)) for e in expired.states + [expired.end]] == [(P.KIND_STORED, 772)] * 2 +
      [(P.KIND_STORED, 432)] and list(sh.grants) == [a_b],
      'at until: states, then the end, and Carol is no longer a recipient')
# The epoch change re-keys too.
old_pk = sh.stream.pubkey()
midnight = P.epoch_end(P.epoch_of(t))
rekey = sh.tick(rng, midnight)
check(len(rekey.states) == 1 and rekey.end is not None and sh.stream.pubkey() != old_pk,
      'a new stream at the epoch change')

# --- Receiving rules: discard silently, and agree with a strict JSON parser ----------------------

e0 = P.epoch_of(now)
a_erin, erin_a, _ = pair('Alice', RELAYS_A, 'Erin', RELAYS_B, T0, checks_on=False)
d_ae = a_erin.outgoing.at(e0)


def raw_state(text: bytes, t: int) -> Event:
    """A state event from Alice to Erin whose plaintext is exactly `text`."""
    return P.sign_event(d_ae.signing_key(), t, P.KIND_STORED, [['d', ''], ['expiration', str(P.epoch_end(e0) + 3600)]],
                        nip44.encrypt(text, d_ae.conversation_key(), os.urandom(32)), rng)


garbage = P.sign_event(d_ae.signing_key(), now + 20, P.KIND_STORED, [['d', ''], ['expiration', str(now + 9999)]],
                       p.b64encode(b'\x02' + os.urandom(200)), rng)
check(P.read_control(erin_a, wire(garbage), now + 21) is None, 'undecryptable state discarded silently')
seq = [1000]


def state_text(**over):
    seq[0] += 1
    body = {'t': 'state', 'seq': seq[0], 'ts': now, 'relays': RELAYS_A}
    body.update(over)
    return json.dumps(body).encode()


good_share = {'until': 0, 'pk': stream.pubkey(), 'key': p.b64encode(stream.key)}
check(P.read_control(erin_a, raw_state(state_text(share=good_share), now + 22), now + 22) is not None,
      'a well-formed state is accepted')
# The dot colour is cosmetic. A short string is kept, whatever the name (an app ignores names it does not
# know); one of another type or size is ignored, not the state with its grant (§8).
for what, value, kept in [('a name', 'teal', 'teal'), ('a name of a later version', 'mauve', 'mauve'),
                          ('32 bytes', 'x' * 32, 'x' * 32), ('33 bytes', 'x' * 33, None), ('empty', '', None),
                          ('a number', 7, None), ('null', None, None)]:
    body = P.decode_plaintext(state_text(share=good_share, color=value))
    check(not raises(lambda: P.check_state(body)) and P.state_color(body) == kept, 'the dot colour: ' + what)
bad_texts = {
    'NaN': state_text().replace(b'"ts": %d' % now, b'"ts": NaN'),
    'Infinity': state_text().replace(b'"ts": %d' % now, b'"ts": Infinity'),
    'number overflow': state_text().replace(b'"ts": %d' % now, b'"ts": 1e400'),
    'integer beyond 2^53': state_text(ts=2 ** 53),
    'float as integer': state_text().replace(b'"ts": %d' % now, b'"ts": %d.0' % now),
    'bool as integer': state_text(seq=True),
    'duplicate member': state_text()[:-1] + b', "seq": 1}',
    'unpaired surrogate': state_text().replace(b'"t": "state"', b'"t": "state", "x": "\\ud800"'),
    'invalid UTF-8': state_text().replace(b'"t": "state"', b'"t": "state", "x": "\xff"'),
    'share.pk not hex': state_text(share=dict(good_share, pk='Z' * 64)),
    'share.pk upper case': state_text(share=dict(good_share, pk=stream.pubkey().upper())),
    'share.pk off the curve': state_text(share=dict(good_share, pk='00' * 32)),
    'share.key 31 bytes': state_text(share=dict(good_share, key=p.b64encode(os.urandom(31)))),
    'share.key non-canonical': state_text(share=dict(good_share, key=p.b64encode(stream.key)[:-2] + 'B=')),
    'share.until negative': state_text(share=dict(good_share, until=-1)),
    'share.until bool': state_text(share=dict(good_share, until=False)),
    'share missing key': state_text(share={'until': 0, 'pk': stream.pubkey()}),
    'relays ws://': state_text(relays=['ws://nos.lol']),
}
for what, text in bad_texts.items():
    t = now + 23 + len(what)
    check(raises(lambda: P.check_state(P.decode_plaintext(text))) and
          P.read_control(erin_a, raw_state(text, t), t) is None, 'state discarded: ' + what)
check(raises(lambda: P.parse_json(b'{"t":"x","a":-Infinity}')), 'parse_json refuses -Infinity')
check(P.parse_json(b'{"t":"x","a":-0.5,"b":9007199254740991}') == {'t': 'x', 'a': -0.5, 'b': 2 ** 53 - 1},
      'parse_json keeps ordinary numbers')
grant = {'pk': stream.pubkey(), 'key': p.b64encode(stream.key), 'until': 0}


def raw_loc(text: bytes, t: int) -> Event:
    return P.sign_event(stream.secret, t, P.KIND_STORED, [['d', ''], ['expiration', str(t + 900)]],
                        nip44.encrypt(text, stream.key, os.urandom(32)), rng)


ok_loc = {'t': 'loc', 'seq': 50, 'ts': 1, 'lat': 1.5, 'lon': -2, 'acc': 3}
check(P.read_stream(grant, raw_loc(json.dumps(ok_loc).encode(), now + 60), 0, now + 60) is not None,
      'a well-formed location is accepted')
for what, over in {'lat 91': {'lat': 91}, 'lon -181': {'lon': -181}, 'acc -1': {'acc': -1}, 'brg 360': {'brg': 360},
                   'spd -1': {'spd': -1}, 'seq 0': {'seq': 0}, 'seq bool': {'seq': True}, 'lat string': {'lat': '1'},
                   'low not bool': {'low': 1}, 'nav.dest too long': {'nav': {'dest': 'x' * 49}}}.items():
    body = dict(ok_loc, **over)
    check(raises(lambda: P.check_loc(body)) and
          P.read_stream(grant, raw_loc(json.dumps(body).encode(), now + 61), 0, now + 61) is None,
          'location discarded: ' + what)
check(P.read_stream(grant, raw_loc(b'{"t":"end","seq":51}', now + 62), 0, now + 62) is None,
      'end without ts discarded')

# --- Forward secrecy -----------------------------------------------------------------------------

e = P.epoch_of(now)
ck_e = bob_a.incoming.at(e).chain_key
P.ratchet(bob_a, P.epoch_end(e) + P.CONTROL_GRACE - 1)
check(bob_a.incoming.epoch == e, 'keys of the previous epoch kept during the grace hour')
P.read_control(bob_a, g_bob, P.epoch_end(e) + P.CONTROL_GRACE)   # any use ratchets
check(bob_a.incoming.epoch == e + 1 and bob_a.outgoing.epoch == e + 1, 'chain keys ratchet when the hour is over')
check(raises(lambda: bob_a.incoming.at(e)) and bob_a.incoming.chain_key != ck_e,
      'an erased epoch cannot be re-derived from what the device stores')
d_next = a_bob.outgoing.at(e + 1)
check(d_next.pubkey() != a_bob.outgoing.at(e).pubkey(), 'channel pubkey changes per epoch')
check(raises(lambda: d_next.at(e)), 'ratchet cannot go backwards')
later = P.epoch_end(e) + 10
g_bob3 = P.state_event(a_bob, RELAYS_A, P.share_grant(0, stream.pubkey(), stream.key), rng, later)
check(P.read_control(bob_a, g_bob3, later + 1) is not None, 'a state of the next epoch is readable')

# --- Signals ---------------------------------------------------------------------------------

sig = P.watch_signal(bob_a, later + 120, rng, later + 10)
w = P.read_signal(a_bob, sig, later + 11)
check(w and w['t'] == 'watch' and w['until'] == later + 120, 'alice reads watch signal')
check(P.read_signal(a_carol, sig, later + 11) is None, 'watch signal bound to its channel')
check(P.read_signal(a_bob, sig, later + 10 + P.SIGNAL_MAX_AGE + 1) is None, 'stale signal ignored')
d_ba = bob_a.outgoing.at(P.epoch_of(later))
junk_sig = P.sign_event(d_ba.signing_key(), later + 12, P.KIND_SIGNAL, [], p.b64encode(b'\x02' + os.urandom(150)), rng)
check(P.read_signal(a_bob, wire(junk_sig), later + 12) is None, 'undecryptable signal discarded silently')

# Relay consent meets the single listening connection (D17). Alice lists her own relay first, so while she
# shares and nobody watches, her app listens only there. Bob's app may not use that relay, so his watch
# signals go only to her other one, and live updates never start. Relay lists keep the sender's order, so
# Bob's app can tell which relay live updates need, and ask for it.
alice_list = ['wss://relay.alice.example', 'wss://nos.lol']
store = {url: Relay() for url in alice_list}            # one model relay per URL
bob_trusted = set(RELAYS_B) | set(P.DEFAULT_RELAYS)     # Bob's own relays and the defaults
st = P.read_control(bob_a, wire(P.state_event(a_bob, alice_list, None, rng, later + 20)), later + 20)
check(st['relays'] == alice_list, "a state carries the sender's relays in its order")
signal_to, _ = P.split_relays(st['relays'], bob_trusted)
for url in signal_to:
    store[url].publish(P.watch_signal(bob_a, later + 200, rng, later + 21))
check(store[alice_list[0]].query() == [] and len(store['wss://nos.lol'].query()) == 1,
      "Bob's watch signal misses the only relay Alice listens on: no live updates")
check(P.missing_listening_relay(st['relays'], bob_trusted) == 'wss://relay.alice.example',
      "Bob's app knows which relay live updates need")
bob_trusted.add('wss://relay.alice.example')            # Bob allows it
signal_to, _ = P.split_relays(st['relays'], bob_trusted)
for url in signal_to:
    store[url].publish(P.watch_signal(bob_a, later + 260, rng, later + 81))
heard = [P.read_signal(a_bob, ev, later + 82) for ev in store[alice_list[0]].query()]
check(P.missing_listening_relay(st['relays'], bob_trusted) is None and len(heard) == 1 and heard[0] is not None,
      'once allowed, his signals reach her listening relay')
check(P.missing_listening_relay(list(reversed(alice_list)), set(P.DEFAULT_RELAYS)) is None,
      'a default relay first: nothing to ask')

# --- Subscriptions ---------------------------------------------------------------------------

seed = os.urandom(32)
e = P.epoch_of(later)
f = P.inbox_filters([a_bob, a_carol], seed, e, later)
authors = f[0]['authors']
check(len(f) == 2 and f[0]['kinds'] == [P.KIND_STORED] and f[1]['kinds'] == [P.KIND_SIGNAL] and
      f[1]['authors'] == authors and f[1]['since'] == later - P.SIGNAL_MAX_AGE,
      'one author list for states and signals: relays cannot tell recipients from other contacts')
check(len(authors) == 8 and authors == sorted(authors), 'inbox authors padded to 8 with decoys, sorted')
check({a_bob.incoming.at(e).pubkey(), a_carol.incoming.at(e).pubkey()} <= set(authors), 'real keys included')
check(P.inbox_filters([a_bob, a_carol], seed, e, later + 500)[0]['authors'] == authors,
      'decoys stable within the epoch (reconnecting reveals nothing)')
check(not set(P.inbox_filters([a_bob, a_carol], seed, e + 1, later)[0]['authors']) & set(authors),
      'nothing in common between two epochs\' filters')
check(a_bob.incoming.at(e + 1).pubkey() not in authors and a_bob.incoming.at(e).pubkey() in authors,
      'a filter holds keys of one epoch only')


def dummy(epoch):
    return P.Contact('x', RELAYS_A, P.Direction(epoch, os.urandom(32)), P.Direction(epoch, os.urandom(32)), '')


check(len(P.inbox_filters([dummy(e) for _ in range(9)], seed, e, later)[0]['authors']) == 16, '9 contacts -> 16 keys')
big = P.inbox_filters([dummy(e) for _ in range(60)], seed, e, later)
check(len(big) == 4 and [len(x['authors']) for x in big] == [50, 50, 14, 14], '64 keys split into filters of <= 50')
check(P.inbox_filters([], seed, e, later) == [], 'no contacts, no subscription')

print('%d checks, %d failures' % (checks, failures))
sys.exit(1 if failures else 0)
