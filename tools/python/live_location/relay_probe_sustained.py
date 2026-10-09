"""Follow-up relay probes: author caps, NIP-40 lag, sustained cadence latency, idle connections.

Usage: relay_probe2.py OUT.json DURATION_S wss://relay1 [...]
  DURATION_S  length of the sustained 1-event-per-5-s run (also the idle-connection check)
"""

import asyncio
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from relay_probe import Conn, make_event, new_key, random_content, KIND_ADDR  # noqa: E402
from nll import primitives as p  # noqa: E402


async def authors_cap(conn, pk):
    out = {}
    for n in (10, 20, 21, 30, 50, 100):
        authors = [p.secp_xonly_pub(new_key()).hex() for _ in range(n - 1)] + [pk]
        events, err = await conn.query('a%d' % n, {'kinds': [KIND_ADDR], 'authors': authors}, timeout=8)
        out[n] = 'ok' if err is None else err
        await conn.close_sub('a%d' % n)
    return out


async def expiry_lag(pub, sub):
    sk = new_key()
    pk = p.secp_xonly_pub(sk).hex()
    exp = int(time.time()) + 3
    r = await pub.publish(make_event(sk, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(exp)]]))
    out = {'publish': r.get('ok'), 'msg': r.get('msg')}
    for after in (5, 15, 40):
        await asyncio.sleep(max(0, exp + after - time.time()))
        events, err = await sub.query('x%d' % after, {'kinds': [KIND_ADDR], 'authors': [pk]}, timeout=8)
        out['served_%ds_after' % after] = len(events) > 0
        await sub.close_sub('x%d' % after)
    return out


async def sustained(pub, sub, duration):
    """One addressable update every 5 s; a second connection keeps a live subscription."""
    sk = new_key()
    pk = p.secp_xonly_pub(sk).hex()
    await sub.send(['REQ', 'live', {'kinds': [KIND_ADDR], 'authors': [pk], 'limit': 0}])
    await sub.wait_for(lambda m: m[0] in ('EOSE', 'CLOSED') and m[1] == 'live')
    sent, latencies, refused, missing = 0, [], [], 0
    t_end = time.monotonic() + duration
    while time.monotonic() < t_end:
        ev = make_event(sk, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(int(time.time()) + 900)]],
                        created_at=int(time.time()) + sent)  # strictly increasing created_at
        t_send = time.monotonic()
        r = await pub.publish(ev)
        sent += 1
        if not r.get('ok'):
            refused.append(r.get('msg'))
        t, msg = await sub.wait_for(lambda m: m[0] == 'EVENT' and m[1] == 'live' and m[2]['id'] == ev.id, timeout=5)
        if msg is not None and msg[0] == 'EVENT':
            latencies.append((t - t_send) * 1000)
        else:
            missing += 1
        await asyncio.sleep(max(0, 5 - (time.monotonic() - t_send)))
    lat = sorted(latencies)
    return {'sent': sent, 'refused': len(refused), 'refused_msgs': sorted(set(refused))[:3], 'missed_live': missing,
            'p50_ms': round(statistics.median(lat)) if lat else None,
            'p95_ms': round(lat[int(0.95 * (len(lat) - 1))]) if lat else None,
            'max_ms': round(lat[-1]) if lat else None}


async def idle(url, duration):
    """Open a subscription and send nothing; report whether the relay closes it within `duration`."""
    c = Conn(url)
    try:
        await c.open()
        await c.send(['REQ', 'idle', {'kinds': [KIND_ADDR], 'authors': [p.secp_xonly_pub(new_key()).hex()]}])
        t, msg = await c.wait_for(lambda m: m[0] in ('CLOSED', '__CLOSED__') or (m[0] == 'NOTICE'), timeout=duration)
        return {'closed': msg is not None, 'after_s': None if msg is None else round(t - (time.monotonic() - duration)),
                'msg': msg}
    except Exception as e:
        return {'error': repr(e)[:200]}
    finally:
        await c.close()


async def probe(url, duration):
    res = {'url': url}
    pub, sub = Conn(url), Conn(url)
    try:
        res['connect_ms'] = round(await pub.open() * 1000)
        await sub.open()
    except Exception as e:
        res['connect_error'] = repr(e)[:300]
        return res
    try:
        idle_task = asyncio.create_task(idle(url, duration))
        res['authors_cap'] = await authors_cap(sub, p.secp_xonly_pub(new_key()).hex())
        res['expiry_lag'] = await expiry_lag(pub, sub)
        res['sustained_5s'] = await sustained(pub, sub, duration)
        res['idle'] = await idle_task
    except Exception as e:
        res['error'] = repr(e)[:300]
    finally:
        await pub.close()
        await sub.close()
    return res


async def main():
    out, duration, urls = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
    results = await asyncio.gather(*(probe(u, duration) for u in urls))
    with open(out, 'w') as f:
        json.dump({'probed_at': int(time.time()), 'duration_s': duration, 'results': results}, f, indent=1)
    for r in results:
        print(json.dumps(r))


if __name__ == '__main__':
    asyncio.run(main())
