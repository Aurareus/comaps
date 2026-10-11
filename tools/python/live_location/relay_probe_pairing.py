"""Checks what pairing (spec §6.3) needs from relays.

Each pairing party signs with its own key, and the joiners' events carry a `p` tag with the inviter's
pairing key. For each relay, with fresh random keys and no AUTH / PoW / payment:
  p_accept    a kind 30484 event with tags d, p, expiration is accepted
  p_live      a live `#p` subscription receives it
  p_stored    a later `#p` query returns the events of two authors with the same `d` (no replacement
              across authors)
  own_replace a newer event from the same author and `d` replaces that author's older one
  authors     an `authors` query returns the inviter-side event

Usage: relay_probe_pairing.py OUT.json wss://relay1 [...]
"""

import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from relay_probe import Conn, KIND_ADDR, make_event, new_key, random_content  # noqa: E402
from nll import primitives as p  # noqa: E402


def pairing_event(sk, d, ptag, exp, created_at=None):
    tags = [['d', d]] + ([['p', ptag]] if ptag else []) + [['expiration', str(exp)]]
    return make_event(sk, KIND_ADDR, random_content(), tags, created_at)


async def probe(url):
    res = {'url': url}
    pub, live, later = Conn(url), Conn(url), Conn(url)
    try:
        await pub.open()
        await live.open()
        now = int(time.time())
        exp = now + 600
        inviter = new_key()
        ipk = p.secp_xonly_pub(inviter).hex()
        j1, j2 = new_key(), new_key()

        await live.send(['REQ', 'live', {'kinds': [KIND_ADDR], '#p': [ipk], 'since': now - 10}])
        await live.wait_for(lambda m: m[0] == 'EOSE' and m[1] == 'live')

        e1 = pairing_event(j1, '0', ipk, exp, now)
        t0 = time.monotonic()
        res['p_accept'] = await pub.publish(e1)
        t, msg = await live.wait_for(lambda m: m[0] == 'EVENT' and m[1] == 'live' and m[2]['id'] == e1.id)
        res['p_live'] = {'received': msg is not None and msg[0] == 'EVENT',
                         'latency_ms': round((t - t0) * 1000) if msg and msg[0] == 'EVENT' else None}
        e2 = pairing_event(j2, '0', ipk, exp, now)
        res['second_author'] = await pub.publish(e2)
        e3 = pairing_event(inviter, '1', None, exp, now)
        res['inviter_event'] = await pub.publish(e3)

        await later.open()
        evs, err = await later.query('q1', {'kinds': [KIND_ADDR], '#p': [ipk]})
        ids = {e['id'] for e in evs}
        res['p_stored'] = {'both_authors': {e1.id, e2.id} <= ids, 'count': len(evs), 'error': err}

        e1b = pairing_event(j1, '0', ipk, exp, now + 1)
        res['own_newer'] = await pub.publish(e1b)
        evs, err = await later.query('q2', {'kinds': [KIND_ADDR], '#p': [ipk]})
        ids = {e['id'] for e in evs}
        res['own_replace'] = {'newer_served': e1b.id in ids, 'older_gone': e1.id not in ids,
                              'other_author_kept': e2.id in ids, 'error': err}
        evs, err = await later.query('q3', {'kinds': [KIND_ADDR], 'authors': [ipk]})
        res['authors'] = {'served': any(e['id'] == e3.id for e in evs), 'error': err}
    except Exception as e:
        res['error'] = repr(e)[:200]
    finally:
        for c in (pub, live, later):
            try:
                await c.close()
            except Exception:
                pass
    return res


async def main():
    out, urls = sys.argv[1], sys.argv[2:]
    results = await asyncio.gather(*(probe(u) for u in urls))
    with open(out, 'w') as f:
        json.dump({'measured_at': int(time.time()), 'results': results}, f, indent=1)
    for r in results:
        print(json.dumps(r))


if __name__ == '__main__':
    asyncio.run(main())
