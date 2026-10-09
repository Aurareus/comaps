"""End-to-end scenario tests of the NLL v1 reference implementation (no network)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nll import primitives as p, protocol as P  # noqa: E402
from nll.nostr import Event  # noqa: E402

failures = 0
checks = 0


def check(cond, what):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        print('FAIL:', what)


def raises(fn):
    try:
        fn()
        return False
    except Exception:
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
    joiner = P.Joiner(P.Invite.from_link(inviter.invite.link()), name_joiner, relays_joiner, rng, now + 5)
    inviter.on_commit(wire(joiner.commit_event(rng, now + 5)), now + 6)
    m1 = inviter.message1(name_inviter, relays_inviter, rng, now + 6)
    seen_by_joiner = joiner.on_message1(wire(m1), now + 7)
    check(seen_by_joiner['name'] == name_inviter, 'joiner sees inviter name')
    m2 = joiner.message2(rng, now + 7)
    req = inviter.on_message2(wire(m2), now + 8)
    check(req['name'] == name_joiner and req['sas'] == joiner.sas, 'inviter sees joiner name and the same code')
    m3, c_inviter = inviter.message3(True, rng, now + 20)
    c_joiner = joiner.on_message3(wire(m3), now + 21)
    check(c_inviter.sas == c_joiner.sas, 'SAS agree')
    check(c_inviter.outgoing.chain_key == c_joiner.incoming.chain_key, 'A->B chain keys agree')
    check(c_inviter.incoming.chain_key == c_joiner.outgoing.chain_key, 'B->A chain keys agree')
    check(c_inviter.outgoing.chain_key != c_inviter.incoming.chain_key, 'directions differ')
    check(c_joiner.name == name_inviter and c_inviter.name == name_joiner, 'names exchanged')
    check(c_joiner.relays == relays_inviter and c_inviter.relays == relays_joiner, 'relays exchanged')
    check(raises(lambda: inviter.on_commit(wire(joiner.commit_event(rng, now + 30)), now + 30)),
          'invite is single-use')
    return c_inviter, c_joiner


# Pairing: Alice invites Bob and Carol.
a_bob, bob_a = pair('Alice', RELAYS_A, 'Bob', RELAYS_B, T0)
a_carol, carol_a = pair('Alice', RELAYS_A, 'Carol', RELAYS_B, T0 + 100)

# Declining: the joiner learns it and gets no contact.
inv = P.Inviter(RELAYS_A, rng, T0)
jn = P.Joiner(inv.invite, 'Dave', RELAYS_B, rng, T0)
inv.on_commit(wire(jn.commit_event(rng, T0)), T0)
jn.on_message1(wire(inv.message1('Alice', RELAYS_A, rng, T0)), T0)
inv.on_message2(wire(jn.message2(rng, T0)), T0)
m3, c = inv.message3(False, rng, T0)
check(c is None and jn.on_message3(wire(m3), T0) is None, 'decline: no contact on either side')

# Without the PSK nothing can be injected: events under a wrong rendezvous key are rejected.
inv = P.Inviter(RELAYS_A, rng, T0)
bad = P.Invite(os.urandom(32), inv.invite.expires_at, RELAYS_A)
check(raises(lambda: inv.on_commit(P.Joiner(bad, 'Mallory', RELAYS_B, rng, T0).commit_event(rng, T0), T0)),
      'wrong psk rejected (envelope)')

# A message 2 that does not open the commitment is rejected, even with the right PSK.
inv = P.Inviter(RELAYS_A, rng, T0)
honest = P.Joiner(inv.invite, 'Bob', RELAYS_B, rng, T0)
other = P.Joiner(inv.invite, 'Mallory', RELAYS_B, rng, T0)
inv.on_commit(wire(honest.commit_event(rng, T0)), T0)
m1 = inv.message1('Alice', RELAYS_A, rng, T0)
other.on_message1(wire(m1), T0)
check(raises(lambda: inv.on_message2(wire(other.message2(rng, T0)), T0)), 'uncommitted ephemeral key rejected')

# Man in the middle who knows the PSK (intercepted invite): it runs one handshake with each side.
# Its key towards Alice is committed before it sees Alice's, and Bob's key is committed before the
# MITM must choose its key towards Bob, so it cannot steer the two codes to match.
alice = P.Inviter(RELAYS_A, rng, T0)
bob = P.Joiner(alice.invite, 'Bob', RELAYS_B, rng, T0)
mitm_to_alice = P.Joiner(alice.invite, 'Bob', RELAYS_B, rng, T0)     # pretends to be Bob
mitm_to_bob = P.Inviter(RELAYS_A, rng, T0)                            # pretends to be Alice
mitm_to_bob.invite = alice.invite
mitm_to_bob.rv_sk = alice.rv_sk
bob_commit = bob.commit_event(rng, T0)                                # intercepted
alice.on_commit(wire(mitm_to_alice.commit_event(rng, T0)), T0)
mitm_to_alice.on_message1(wire(alice.message1('Alice', RELAYS_A, rng, T0)), T0)
alice_view = alice.on_message2(wire(mitm_to_alice.message2(rng, T0)), T0)
mitm_to_bob.on_commit(wire(bob_commit), T0)
bob.on_message1(wire(mitm_to_bob.message1('Alice', RELAYS_A, rng, T0)), T0)
bob_m2 = bob.message2(rng, T0)
mitm_to_bob.on_message2(wire(bob_m2), T0)
check(alice_view['sas'] != bob.sas, 'MITM with the PSK yields different codes on the two screens')

# Expired invite.
check(raises(lambda: P.Joiner(inv.invite, 'Late', RELAYS_B, rng, inv.invite.expires_at)), 'expired invite refused')

# Alice shares with Bob (1 h) and Carol (until stopped).
now = T0 + 200
stream = P.Stream.create(rng)
g_bob = P.control_event(a_bob, P.state_body(1, now, RELAYS_A, P.share_grant(now + 3600, stream.pubkey(), stream.key)),
                        rng, now)
g_carol = P.control_event(a_carol, P.state_body(1, now, RELAYS_A, P.share_grant(0, stream.pubkey(), stream.key)),
                          rng, now)
state_bob = P.read_control(bob_a, g_bob, now + 1)
state_carol = P.read_control(carol_a, g_carol, now + 1)
grant_bob = state_bob['share']
grant_carol = state_carol['share']
check(state_bob['relays'] == RELAYS_A and grant_bob['until'] == now + 3600, 'bob reads grant')
check(grant_carol['pk'] == stream.pubkey() and grant_carol['until'] == 0, 'carol reads grant')
check(P.read_control(carol_a, g_bob, now + 1) is None, 'carol cannot read bob grant')
check(P.read_control(bob_a, g_bob, now + 2) is None, 'replayed grant rejected (seq)')

fix = {'ts': now * 1000, 'lat': 52.5200066, 'lon': 13.404954, 'acc': 8.0, 'spd': 1.4, 'brg': 271.0}
loc1 = stream.location_event(fix, rng, now + 5)
check(len(loc1.content) == 432, 'location content has constant length (432 chars)')
check(len(g_bob.content) == 772, 'control content has constant length (772 chars)')
check(len(P.control_event(a_bob, P.state_body(9, now, RELAYS_A), rng, now).content) == 772,
      'control end has the same length as a grant')
r1 = P.read_stream(grant_bob, loc1, 0, now + 6)
check(r1 and r1['lat'] == 52.5200066 and r1['seq'] == 1, 'bob reads location')
check(P.read_stream(grant_carol, loc1, 0, now + 6) is not None, 'carol reads location')
check(P.read_stream(grant_bob, loc1, 1, now + 6) is None, 'location replay rejected (seq)')

# Tampering: flip a ciphertext byte -> MAC failure; resign so the envelope is valid.
raw = bytearray(p.b64decode(loc1.content))
raw[40] ^= 1
tampered = P.sign_event(stream.secret, loc1.created_at, loc1.kind, loc1.tags, p.b64encode(bytes(raw)), rng)
check(raises(lambda: P.read_stream(grant_bob, tampered, 0, now + 6)), 'tampered ciphertext rejected')
# A recipient forging a location under its own key is rejected (pubkey must be the stream key).
forger = P.Stream(os.urandom(32), stream.key)
check(P.read_stream(grant_bob, forger.location_event(fix, rng, now + 7), 0, now + 7) is None,
      'recipient cannot forge sharer locations')
# Expired events are ignored.
check(P.read_stream(grant_bob, loc1, 0, now + 5 + P.TTL_LOCATION) is None, 'expired location ignored')

# Revoke Carol: rotate the stream, new grant to Bob only, a share-less state to Carol, end on the old stream.
now += 60
old = stream
stream = P.Stream.create(rng)
g_bob2 = P.control_event(a_bob, P.state_body(2, now, RELAYS_A, P.share_grant(now + 3600, stream.pubkey(), stream.key)),
                         rng, now)
e_carol = P.control_event(a_carol, P.state_body(2, now, RELAYS_A), rng, now)
old_end = old.end_event('rotated', rng, now)
grant_bob = P.read_control(bob_a, g_bob2, now + 1)['share']
check(grant_bob['pk'] == stream.pubkey(), 'bob gets rotated grant')
check('share' not in P.read_control(carol_a, e_carol, now + 1), 'carol sees the share end')
check(P.read_control(carol_a, g_carol, now + 2) is None, 'old grant cannot be replayed to carol after the end')
check(P.read_stream(grant_carol, old_end, 1, now + 1)['t'] == 'end', 'carol sees old stream end')
loc2 = stream.location_event(fix, rng, now + 5)
check(P.read_stream(grant_bob, loc2, 0, now + 6) is not None, 'bob reads post-revocation location')
check(P.read_stream(grant_carol, loc2, 1, now + 6) is None, 'carol rejects new stream (unknown pubkey)')
check(raises(lambda: P.open_sealed(loc2.content, p.b64decode(grant_carol['key']))),
      'carol cannot decrypt post-revocation location even ignoring the pubkey')

# Epoch rollover: chain keys ratchet forward, the past is unreachable.
e = P.epoch_of(now)
d_next = a_bob.outgoing.at(e + 1)
check(d_next.pubkey() != a_bob.outgoing.at(e).pubkey(), 'channel pubkey changes per epoch')
check(raises(lambda: d_next.at(e)), 'ratchet cannot go backwards')
later = P.epoch_end(e) + 10
g_bob3 = P.control_event(a_bob, P.state_body(3, later, RELAYS_A, P.share_grant(0, stream.pubkey(), stream.key)),
                         rng, later)
check(P.read_control(bob_a, g_bob3, later + 1) is not None, 'grant in next epoch readable')

# Watch signal Bob -> Alice.
sig = P.watch_signal(bob_a, now + 120, rng, now + 10)
w = P.read_signal(a_bob, sig, now + 11)
check(w and w['t'] == 'watch' and w['until'] == now + 120, 'alice reads watch signal')
check(P.read_signal(a_carol, sig, now + 11) is None, 'watch signal bound to its channel')

print('%d checks, %d failures' % (checks, failures))
sys.exit(1 if failures else 0)
