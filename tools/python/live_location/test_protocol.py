"""End-to-end scenario tests of the NLL v1 reference implementation (no network)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nll import noise, primitives as p, protocol as P  # noqa: E402
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


def pair(name_inviter, relays_inviter, name_joiner, relays_joiner, now):
    inviter = P.Inviter(relays_inviter, rng, now)
    link = inviter.invite.link()
    joiner = P.Joiner(P.Invite.from_link(link), name_joiner, relays_joiner, rng, now + 5)
    m0 = joiner.commit_event(rng, now + 5)
    m1 = inviter.on_commit(wire(m0), rng, now + 6)
    check(inviter.on_commit(wire(m0), rng, now + 6) is None, 'a copy of step 0 from another relay is ignored')
    m2 = joiner.on_message1(wire(m1), rng, now + 7)
    check(joiner.on_message1(wire(m1), rng, now + 7) is None, 'a copy of step 1 is not answered again')
    req = inviter.on_message2(wire(m2), now + 8)
    check(req['name'] == name_joiner and req['sas'] == joiner.sas, 'inviter sees joiner name and the same code')
    m3, c_inviter = inviter.message3(True, name_inviter, relays_inviter, rng, now + 20)
    c_joiner = joiner.on_message3(wire(m3), now + 21)
    check(c_inviter.sas == c_joiner.sas, 'SAS agree')
    check(c_inviter.outgoing.chain_key == c_joiner.incoming.chain_key, 'A->B chain keys agree')
    check(c_inviter.incoming.chain_key == c_joiner.outgoing.chain_key, 'B->A chain keys agree')
    check(c_inviter.outgoing.chain_key != c_inviter.incoming.chain_key, 'directions differ')
    check(c_joiner.name == name_inviter and c_inviter.name == name_joiner, 'names exchanged')
    check(c_joiner.relays == relays_inviter and c_inviter.relays == relays_joiner, 'relays exchanged')
    check(None is inviter.k1 is inviter.k2 is joiner.k1 is joiner.k2 is inviter.invite.psk,
          'pairing roots and PSK erased once the channel keys exist')
    late = P.Joiner(P.Invite.from_link(link), 'Late', relays_joiner, rng, now + 30)
    check(raises(lambda: inviter.on_commit(wire(late.commit_event(rng, now + 30)), rng, now + 30)),
          'invite is single-use')
    return c_inviter, c_joiner


def start_pairing(now, name='Bob'):
    """Inviter and joiner up to (excluding) step 1 being processed by the joiner."""
    inviter = P.Inviter(RELAYS_A, rng, now)
    joiner = P.Joiner(inviter.invite, name, RELAYS_B, rng, now)
    m1 = inviter.on_commit(wire(joiner.commit_event(rng, now)), rng, now)
    return inviter, joiner, m1


def forged_step1(invite, rng_, now):
    """What anyone holding the invite (an intercepted link) can publish as step 1."""
    hs = noise.HandshakeState(P.NOISE_PATTERN, True, invite.prologue(), invite.psk, rng_(32))
    payload = P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL)
    return P.rendezvous_event(invite.rendezvous_key(), 1, p.b64encode(hs.write_message(payload)), invite, rng_, now)


# --- Pairing ---------------------------------------------------------------------------------

a_bob, bob_a = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0)
a_carol, carol_a = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0 + 100)

# Step 1 carries nothing: an intercepted link (PSK) lets an eavesdropper decrypt step 1, which must
# not reveal the inviter's name or relays any more.
inv, jn, m1 = start_pairing(T0)
eavesdropper = noise.HandshakeState(P.NOISE_PATTERN, False, inv.invite.prologue(), inv.invite.psk, os.urandom(32))
step1_plain = P.decode_plaintext(eavesdropper.read_message(p.b64decode(m1.content)))
check(step1_plain == {'t': 'pair1'}, 'step 1 reveals nothing to someone holding the invite')

# Declining: the joiner learns it and gets no contact.
inv, jn, m1 = start_pairing(T0, 'Dave')
inv.on_message2(wire(jn.on_message1(wire(m1), rng, T0)), T0)
m3, c = inv.message3(False, 'Alice', RELAYS_A, rng, T0)
check(c is None and jn.on_message3(wire(m3), T0) is None, 'decline: no contact on either side')

# Without the PSK nothing can be injected: events under a wrong rendezvous key are rejected.
inv = P.Inviter(RELAYS_A, rng, T0)
bad = P.Invite(os.urandom(32), inv.invite.expires_at, RELAYS_A)
check(raises(lambda: inv.on_commit(P.Joiner(bad, 'Mallory', RELAYS_B, rng, T0).commit_event(rng, T0), rng, T0),
             ValueError) and inv.commit is None, 'wrong psk rejected (envelope) without using up the invite')

# Single use, joiner side: it answers exactly one step 1. A second, different step 1 (which anyone
# holding the invite can sign) aborts, before and after step 2 was sent. Otherwise an attacker could
# learn the joiner's key from step 2 and then grind its own key offline until the codes match.
inv, jn, m1 = start_pairing(T0)
check(raises(lambda: jn.on_message1(wire(forged_step1(inv.invite, rng, T0)), rng, T0), ValueError) is False and
      jn.step2 is not None, 'joiner answers the first step 1')
inv, jn, m1 = start_pairing(T0)
jn.on_message1(wire(m1), rng, T0)
check(raises(lambda: jn.on_message1(wire(forged_step1(inv.invite, rng, T0)), rng, T0), P.PairingAborted),
      'joiner aborts on a second, different step 1 after answering')
inv, jn, m1 = start_pairing(T0)
check(raises(lambda: jn.on_message1(wire(P.rendezvous_event(inv.rv_sk, 1, p.b64encode(os.urandom(560)), inv.invite,
                                                            rng, T0)), rng, T0), P.PairingAborted),
      'joiner aborts on an undecryptable step 1 signed with the invite key')

# Single use, inviter side.
inv, jn, m1 = start_pairing(T0)
other = P.Joiner(inv.invite, 'Mallory', RELAYS_B, rng, T0)
check(raises(lambda: inv.on_commit(wire(other.commit_event(rng, T0)), rng, T0), P.PairingAborted),
      'inviter aborts on a second, different step 0')
inv, jn, m1 = start_pairing(T0)
other = P.Joiner(inv.invite, 'Mallory', RELAYS_B, rng, T0)
check(raises(lambda: inv.on_message2(wire(other.on_message1(wire(m1), rng, T0)), T0), P.PairingAborted),
      'step 2 that does not open the commitment aborts')
inv, jn, m1 = start_pairing(T0)
m2 = jn.on_message1(wire(m1), rng, T0)
inv.on_message2(wire(m2), T0)
other = P.Joiner(inv.invite, 'Mallory', RELAYS_B, rng, T0)
check(raises(lambda: inv.on_message2(wire(other.on_message1(wire(m1), rng, T0)), T0), P.PairingAborted),
      'inviter aborts on a second, different step 2')

# The code depends only on the keys. Same PSK and ephemeral keys, different step 2 payloads (here
# the joiner's name): the handshake hash differs, the code does not. With a code taken from the
# hash, a man in the middle could vary the step 2 payload it sends to the inviter until the
# inviter's code equals the joiner's (~1e6 cheap tries); taken from the keys, it has nothing to vary.
psk, e_i, e_r = os.urandom(32), os.urandom(32), os.urandom(32)
inv0 = P.Inviter(RELAYS_A, rng, T0)
codes, hashes = set(), set()
for name in ('Bob', 'Bob ', 'Bob  ', 'Robert'):
    i = noise.HandshakeState(P.NOISE_PATTERN, True, inv0.invite.prologue(), psk, e_i)
    r = noise.HandshakeState(P.NOISE_PATTERN, False, inv0.invite.prologue(), psk, e_r)
    r.read_message(i.write_message(P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL)))
    i.read_message(r.write_message(P.encode_plaintext({'t': 'pair2', 'name': name, 'relays': RELAYS_B},
                                                      P.SIZE_CONTROL)))
    hashes.add(i.handshake_hash())
    codes.add(P.sas_digits(i.ss.split()[2]))
check(len(hashes) == 4 and len(codes) == 1, 'code independent of payloads (handshake hash is not)')

# Man in the middle who knows the PSK (intercepted invite) runs one handshake with each side. Its key
# towards Alice is committed before it sees Alice's, and Bob's key is committed before the MITM must
# choose its key towards Bob; each side takes one event per step, so it cannot retry.
alice = P.Inviter(RELAYS_A, rng, T0)
bob = P.Joiner(alice.invite, 'Bob', RELAYS_B, rng, T0)
mitm_to_alice = P.Joiner(alice.invite, 'Bob', RELAYS_B, rng, T0)     # pretends to be Bob
bob_commit = bob.commit_event(rng, T0)                                # intercepted, never reaches Alice
a1 = alice.on_commit(wire(mitm_to_alice.commit_event(rng, T0)), rng, T0)
alice_view = alice.on_message2(wire(mitm_to_alice.on_message1(wire(a1), rng, T0)), T0)
bob.on_message1(wire(forged_step1(alice.invite, rng, T0)), rng, T0)  # the MITM's step 1 towards Bob
check(alice_view['sas'] != bob.sas, 'MITM with the PSK yields different codes on the two screens')

# Expired invite.
check(raises(lambda: P.Joiner(inv.invite, 'Late', RELAYS_B, rng, inv.invite.expires_at)), 'expired invite refused')

# Relays: wss:// only; ws:// only to a loopback host.
for url in ('wss://nos.lol', 'ws://127.0.0.1:7777', 'ws://localhost', 'ws://[::1]:7777/'):
    check(P.check_relays([url]) == [url], 'relay url accepted: ' + url)
for url in ('ws://nos.lol', 'ws://192.168.1.2:7777', 'ws://127.0.0.1.example.com', 'ws://localhost@evil.example',
            'http://nos.lol', 'wss://' + 'x' * 60):
    check(raises(lambda: P.check_relays([url])), 'relay url refused: ' + url)
plain = P.Invite(os.urandom(32), T0 + 600, ['wss://nos.lol'])
plain.relays = ['ws://nos.lol']
check(raises(lambda: P.Invite.from_link(plain.link())), 'invite with a ws:// relay refused')

# --- Sharing ---------------------------------------------------------------------------------

now = T0 + 200
alice_share = P.Sharer(RELAYS_A)
evs = alice_share.start({a_bob: now + 3600, a_carol: 0}, rng, now)
check(len(evs) == 2 and all(e.kind == P.KIND_STORED for e in evs), 'start: one state per recipient')
bob_view, carol_view = P.Following(), P.Following()
for ev in evs:
    for contact, view in ((bob_a, bob_view), (carol_a, carol_view)):
        st = P.read_control(contact, wire(ev), now + 1)
        if st:
            view.on_state(st, now + 1)
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

# Tampering: flip a ciphertext byte -> MAC failure; resign so the envelope is valid.
raw = bytearray(p.b64decode(loc1.content))
raw[40] ^= 1
tampered = P.sign_event(stream.secret, loc1.created_at, loc1.kind, loc1.tags, p.b64encode(bytes(raw)), rng)
check(raises(lambda: P.read_stream(bob_view.grant, tampered, 0, now + 6)), 'tampered ciphertext rejected')
# A recipient forging a location under its own key is rejected (pubkey must be the stream key).
forger = P.Stream(os.urandom(32), stream.key)
check(P.read_stream(bob_view.grant, forger.location_event(fix, rng, now + 7), 0, now + 7) is None,
      'recipient cannot forge sharer locations')
# Expired events are ignored.
check(P.read_stream(bob_view.grant, loc1, 0, now + 5 + P.TTL_LOCATION) is None, 'expired location ignored')

# --- Revocation: what a removed recipient sees must not depend on whether the share goes on ---


def deliver(events, views, t):
    for ev in events:
        for contact, view in views.items():
            st = P.read_control(contact, wire(ev), t)
            if st is not None:
                view.on_state(st, t)


def revocation(remove_only_carol: bool):
    """Alice shares with Bob and Carol, then either removes Carol or stops sharing altogether. Returns what
    anyone watching the relays sees, and what Carol can decrypt if she keeps the old stream key."""
    a_b, b_a = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0)
    a_c, c_a = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0)
    t = T0 + 300
    sh = P.Sharer(RELAYS_A)
    bob, carol = P.Following(), P.Following()
    deliver(sh.start({a_b: 0, a_c: 0}, rng, t), {b_a: bob, c_a: carol}, t)
    first = wire(sh.location(fix, rng, t + 1))
    bob.on_stream(first, t + 1)
    carol.on_stream(first, t + 1)
    old_pk, carol_key = carol.grant['pk'], carol.grant['key']
    t += 60
    published = sh.change({a_b: 0}, rng, t) if remove_only_carol else sh.stop(rng, t)
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
                                   'published': published, 't': t}


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
deliver(ctx['published'], {ctx['b_a']: bob}, t)
check(bob.grant['pk'] == sh.stream.pubkey() and bob.position is not None,
      'Bob switched to the new stream on its grant and keeps the last position meanwhile')
check(bob.on_stream(wire(ctx['published'][-1]), t) is None and bob.grant is not None,
      'the old stream\'s end does not end Bob\'s view')
loc2 = wire(sh.location(fix, rng, sh.not_before))
check(bob.on_stream(loc2, sh.not_before) is not None, 'Bob reads the new stream')
check(raises(lambda: P.open_sealed(loc2.content, p.b64decode(ctx['carol_key']))),
      'Carol cannot decrypt the new stream with the old key')

# Time limits end on time: Carol's `until` passes and she is removed exactly as above.
a_b, b_a = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0)
a_c, c_a = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0)
t = T0 + 300
sh = P.Sharer(RELAYS_A)
carol = P.Following()
deliver(sh.start({a_b: 0, a_c: t + 600}, rng, t), {c_a: carol}, t)
check(sh.tick(rng, t + 599) == [], 'nothing changes before the time limit')
check(carol.on_stream(wire(sh.location(fix, rng, t + 599)), t + 600) is None and carol.grant is None,
      'the viewer enforces until locally as well')
expired = sh.tick(rng, t + 600)
check([(e.kind, len(e.content)) for e in expired] == [(P.KIND_STORED, 772)] * 2 + [(P.KIND_STORED, 432)] and
      list(sh.grants) == [a_b], 'at until: states, then the end, and Carol is no longer a recipient')
# The epoch change re-keys too.
old_pk = sh.stream.pubkey()
midnight = P.epoch_end(P.epoch_of(t))
rekey = sh.tick(rng, midnight)
check(len(rekey) == 2 and sh.stream.pubkey() != old_pk, 'a new stream at the epoch change')

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
