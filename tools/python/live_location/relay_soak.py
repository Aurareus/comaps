"""Soak test: one addressable update every 5 s per relay for DURATION_S, with reconnects.

Measures per relay: accepted/refused publishes, publisher/subscriber disconnects, live
deliveries missed (not seen by the subscriber within 5 s) and delivery latency percentiles.
Usage: relay_soak.py OUT.json DURATION_S wss://relay1 [...]
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


class Side:
    def __init__(self, url, on_open=None):
        self.url = url
        self.conn = None
        self.disconnects = 0
        self.on_open = on_open

    async def ensure(self):
        if self.conn is not None and self.conn.ws is not None and self.conn.ws.state.name == 'OPEN':
            return True
        if self.conn is not None:
            self.disconnects += 1
            await self.conn.close()
        self.conn = Conn(self.url)
        try:
            await self.conn.open()
            if self.on_open:
                await self.on_open(self.conn)
            return True
        except Exception:
            self.conn = None
            await asyncio.sleep(5)
            return False


async def soak(url, duration):
    sk = new_key()
    pk = p.secp_xonly_pub(sk).hex()

    async def subscribe(conn):
        await conn.send(['REQ', 'soak', {'kinds': [KIND_ADDR], 'authors': [pk], 'limit': 0}])

    pub, sub = Side(url), Side(url, subscribe)
    sent = accepted = 0
    refused, latencies = [], []
    missed = 0
    seq = 0
    t_end = time.monotonic() + duration
    while time.monotonic() < t_end:
        t_loop = time.monotonic()
        if not await pub.ensure() or not await sub.ensure():
            continue
        ev = make_event(sk, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(int(time.time()) + 900)]],
                        created_at=int(time.time()) + seq)
        seq += 1
        t_send = time.monotonic()
        try:
            r = await pub.conn.publish(ev, timeout=10)
        except Exception:
            continue
        sent += 1
        if r.get('ok'):
            accepted += 1
        else:
            refused.append(r.get('msg'))
        try:
            t, msg = await sub.conn.wait_for(lambda m: m[0] == 'EVENT' and m[1] == 'soak' and m[2]['id'] == ev.id,
                                             timeout=5)
        except Exception:
            t, msg = None, None
        if msg is not None and msg[0] == 'EVENT':
            latencies.append((t - t_send) * 1000)
        else:
            missed += 1
        await asyncio.sleep(max(0, 5 - (time.monotonic() - t_loop)))
    for side in (pub, sub):
        if side.conn:
            await side.conn.close()
    lat = sorted(latencies)
    pct = lambda q: round(lat[int(q * (len(lat) - 1))]) if lat else None  # noqa: E731
    return {'url': url, 'sent': sent, 'accepted': accepted, 'refused': len(refused),
            'refused_msgs': sorted(set(refused))[:3], 'missed_live_5s': missed,
            'pub_disconnects': pub.disconnects, 'sub_disconnects': sub.disconnects,
            'p50_ms': round(statistics.median(lat)) if lat else None, 'p95_ms': pct(0.95), 'p99_ms': pct(0.99),
            'max_ms': round(lat[-1]) if lat else None}


async def main():
    out, duration, urls = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
    started = int(time.time())
    results = await asyncio.gather(*(soak(u, duration) for u in urls))
    with open(out, 'w') as f:
        json.dump({'started_at': started, 'duration_s': duration, 'results': results}, f, indent=1)
    for r in results:
        print(json.dumps(r))


if __name__ == '__main__':
    asyncio.run(main())
