"""Generates the NLL v1 test vectors (deterministic). Usage: make_vectors.py [OUT.json]

Every random input is drawn from a recording RNG and written to the vector under the name of
the step that consumed it, in consumption order, so that another implementation can replay
each step with explicit inputs and compare every intermediate value and the final events.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nll import nip44, primitives as p, protocol as P  # noqa: E402
from nll.nostr import Event, serialize  # noqa: E402


class RecordingRng(P.TestRng):
    def __init__(self, seed):
        super().__init__(seed)
        self.log = []

    def __call__(self, n):
        v = super().__call__(n)
        self.log.append(v.hex())
        return v

    def take(self):
        out, self.log = self.log, []
        return out


def ev_dict(ev: Event) -> dict:
    d = ev.to_dict()
    d['serialized'] = serialize(ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content).decode('utf-8')
    return d


def main():
    rng = RecordingRng(b'nll1 test vectors')
    T = 1_760_000_000
    out = {'description': 'NLL v1 test vectors. All times are unix seconds. Random inputs are listed per step in '
                          'consumption order.', 'version': 1}

    # 1. Key derivation helper.
    prk = bytes(range(32))
    out['derive_secp_key'] = [{'prk': prk.hex(), 'purpose': pur, 'secret': P.derive_secp_key(prk, pur).hex(),
                               'pubkey': p.secp_xonly_pub(P.derive_secp_key(prk, pur)).hex()}
                              for pur in ('rv-sign', 'ctl-sign')]

    # 2. Plaintext padding.
    sample = {'t': 'end', 'seq': 7, 'ts': T}
    out['plaintext'] = {'object': sample, 'size_class': P.SIZE_STREAM,
                        'encoded_hex': P.encode_plaintext(sample, P.SIZE_STREAM).hex()}

    # 3. Pairing.
    relays_a = ['wss://nos.lol', 'wss://nostr.mom', 'wss://relay.primal.net']
    relays_b = ['wss://nos.lol', 'wss://relay.nostr.net']
    inviter = P.Inviter(relays_a, rng, T)
    inv_rand = rng.take()
    invite = inviter.invite
    pairing = {'now': T, 'invite': {'psk': invite.psk.hex(), 'inviter_pairing_secret': inviter.isk.hex(),
                                    'inviter_pairing_pubkey': invite.ipk.hex(), 'expires_at': invite.expires_at,
                                    'relays': relays_a, 'encoded_hex': invite.encode().hex(), 'link': invite.link(),
                                    'mac_key': inviter.mac_key.hex()},
               'inviter_random': inv_rand}   # [psk, inviter's pairing secret, inviter's Noise ephemeral secret]
    joiner = P.Joiner(P.Invite.from_link(invite.link()), 'Bob', relays_b, rng, T + 5)
    pairing['joiner_random'] = rng.take()   # [joiner's pairing secret, joiner's Noise ephemeral secret]
    m0 = joiner.commit_event(rng, T + 5)
    pairing['step0_commit'] = {'joiner_pairing_secret': joiner.jsk.hex(), 'joiner_pairing_pubkey': joiner.jpk.hex(),
                               'joiner_ephemeral_public': p.x25519_public(joiner.e).hex(),
                               'commitment': joiner.c.hex(),
                               'mac': p.hmac_sha256(joiner.mac_key, joiner.jpk + joiner.c).hex(),
                               'random': rng.take(), 'event': ev_dict(m0)}
    pairing['prologue_hex'] = invite.prologue(joiner.jpk, joiner.c).hex()
    m1 = inviter.on_event(m0, rng, T + 6).publish
    pairing['step1_noise1'] = {'payload_hex': P.encode_plaintext({'t': 'pair1'}, P.SIZE_CONTROL).hex(),
                               'random': rng.take(), 'noise_message_hex': p.b64decode(m1.content).hex(),
                               'event': ev_dict(m1)}
    m2 = joiner.on_event(m1, rng, T + 7).publish
    pairing['step2_noise2'] = {'payload_hex': P.encode_plaintext({'t': 'pair2', 'name': 'Bob', 'relays': relays_b},
                                                                 P.SIZE_CONTROL).hex(),
                               'random': rng.take(), 'noise_message_hex': p.b64decode(m2.content).hex(),
                               'event': ev_dict(m2)}
    k_i2r, k_r2i = joiner.k1, joiner.k2
    req = inviter.on_event(m2, rng, T + 8).show_code
    decided_at = T + 20
    e_p = P.epoch_of(decided_at - P.MAX_FUTURE_SKEW)
    pair3 = {'t': 'pair3', 'ok': True, 'name': 'Alice', 'relays': relays_a, 'epoch': e_p}
    done = inviter.decide(True, 'Alice', relays_a, rng, decided_at)
    m3, c_a = done.publish, done.contact
    pairing['step3_confirm'] = {'now': decided_at, 'confirm_key': P.confirm_key(k_i2r).hex(),
                                'plaintext_hex': P.encode_plaintext(pair3, P.SIZE_CONTROL).hex(),
                                'random': rng.take(), 'event': ev_dict(m3)}
    fin = joiner.on_event(m3, rng, T + 21)
    c_b = fin.contact
    pairing['joiner_confirmation'] = {'now': T + 21, 'plaintext_hex': P.encode_plaintext(
                                          P.state_body(1, T + 21, relays_b), P.SIZE_CONTROL).hex(),
                                      'random': rng.take(), 'event': ev_dict(fin.publish),
                                      'confirms_on_inviter_side': P.read_control(c_a, fin.publish, T + 22) is not None}
    pairing['result'] = {'handshake_hash': inviter.handshake_hash.hex(), 'split_i2r': k_i2r.hex(),
                         'split_r2i': k_r2i.hex(), 'sas': c_a.sas, 'pairing_epoch': e_p,
                         'shown_to_inviter': req}
    chains = []
    for name, root in (('inviter_to_joiner', k_i2r), ('joiner_to_inviter', k_r2i)):
        d0 = P.Direction.from_root(root, e_p)
        for k in (0, 1, 2):
            d = d0.at(e_p + k)
            chains.append({'direction': name, 'epoch': e_p + k, 'chain_key': d.chain_key.hex(),
                           'signing_secret': d.signing_key().hex(), 'pubkey': d.pubkey(),
                           'conversation_key': d.conversation_key().hex()})
    pairing['channel_keys'] = chains
    out['pairing'] = pairing
    assert c_b.sas == c_a.sas

    # 4. Grant, location, stream end, control end, signal.
    now = T + 200
    stream = P.Stream.create(rng)
    st_rand = rng.take()
    grant = P.share_grant(now + 3600, stream.pubkey(), stream.key)
    g = P.control_event(c_a, P.state_body(1, now, relays_a, grant), rng, now)
    out['state_with_grant'] = {'now': now, 'stream_random': st_rand, 'stream_secret': stream.secret.hex(),
                               'stream_pubkey': stream.pubkey(), 'stream_key': stream.key.hex(),
                               'plaintext_hex': P.encode_plaintext(P.state_body(1, now, relays_a, grant),
                                                                   P.SIZE_CONTROL).hex(),
                               'random': rng.take(), 'event': ev_dict(g),
                               'decrypted': P.read_control(c_b, g, now + 1)}
    fix = {'ts': (now + 5) * 1000, 'lat': 52.5200066, 'lon': 13.404954, 'acc': 8.0, 'spd': 1.4, 'brg': 271.0}
    loc = stream.location_event(fix, rng, now + 5)
    body = {'t': 'loc', 'seq': 1}
    body.update(fix)
    grant = out['state_with_grant']['decrypted']['share']
    out['location'] = {'now': now + 5, 'plaintext_hex': P.encode_plaintext(body, P.SIZE_STREAM).hex(),
                       'random': rng.take(), 'event': ev_dict(loc),
                       'decrypted': P.read_stream(grant, loc, 0, now + 6)}
    se = stream.end_event(rng, now + 30)
    end_body = {'t': 'end', 'seq': 2, 'ts': now + 30}
    out['stream_end'] = {'now': now + 30, 'plaintext_hex': P.encode_plaintext(end_body, P.SIZE_STREAM).hex(),
                         'random': rng.take(), 'event': ev_dict(se)}
    ce = P.control_event(c_a, P.state_body(2, now + 30, relays_a), rng, now + 30)
    out['state_without_share'] = {'now': now + 30, 'random': rng.take(), 'event': ev_dict(ce)}
    sig = P.watch_signal(c_b, now + 150, rng, now + 40)
    out['signal'] = {'now': now + 40, 'random': rng.take(), 'event': ev_dict(sig)}

    # 5. Inbox subscription of Alice at the pairing epoch: Bob's channel key plus 7 decoys.
    decoy_seed = bytes(range(32, 64))
    out['inbox_filters'] = {'decoy_seed': decoy_seed.hex(), 'epoch': e_p, 'now': now,
                            'decoys': P.decoy_keys(decoy_seed, e_p, 7),
                            'filters': P.inbox_filters([c_a], decoy_seed, e_p, now)}

    # 6. NIP-44 with a protocol conversation key (spot check of the profile).
    nonce = bytes(range(32))
    pt = P.encode_plaintext({'t': 'end', 'seq': 1, 'ts': T}, P.SIZE_STREAM)
    out['nip44_profile'] = {'conversation_key': stream.key.hex(), 'nonce': nonce.hex(), 'plaintext_hex': pt.hex(),
                            'payload': nip44.encrypt(pt, stream.key, nonce)}

    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors',
                                                              'nll1_vectors.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write('\n')
    print('wrote', path)


if __name__ == '__main__':
    main()
