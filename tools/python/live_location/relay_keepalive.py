"""Measures how often relays send WebSocket PING frames to an idle client.

Every server ping wakes a phone's radio, so this sets the floor of the battery cost of keeping a
connection open (for example to hear viewers' watch signals). Client-side pings are disabled, so
only the server's keep-alive is observed.

Usage: relay_keepalive.py OUT.json DURATION_S wss://relay1 [...]
"""

import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from websockets.asyncio.client import connect  # noqa: E402

from relay_probe import new_key, ssl_context, KIND_ADDR  # noqa: E402
from nll import primitives as p  # noqa: E402


class PingCounter(logging.Handler):
    """websockets logs every received frame at DEBUG level as '< PING ...' on the connection's logger."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.pings = []

    def emit(self, record):
        if record.getMessage().startswith('< PING'):
            self.pings.append(time.monotonic())


def connection_logger(n):
    """A logger of its own per connection, so that pings are attributed to the right relay."""
    logger = logging.getLogger('relay_keepalive.%d' % n)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    counter = PingCounter()
    logger.addHandler(counter)
    return logger, counter


async def watch(n, url, duration):
    res = {'url': url}
    logger, counter = connection_logger(n)
    try:
        ws = await connect(url, ssl=ssl_context(url), open_timeout=15, ping_interval=None, logger=logger,
                           proxy=True if url.startswith('wss://') else None)
    except Exception as e:
        res['connect_error'] = repr(e)[:200]
        return res
    t0 = time.monotonic()
    await ws.send(json.dumps(['REQ', 'idle', {'kinds': [KIND_ADDR], 'authors': [p.secp_xonly_pub(new_key()).hex()]}]))
    closed = None
    try:
        while time.monotonic() - t0 < duration:
            try:
                await asyncio.wait_for(ws.recv(), timeout=duration - (time.monotonic() - t0))
            except asyncio.TimeoutError:
                break
    except Exception as e:
        closed = repr(e)[:120]
    pings = [round(t - t0, 1) for t in counter.pings]
    gaps = [round(b - a, 1) for a, b in zip([0.0] + pings, pings)]
    res.update({'duration_s': round(time.monotonic() - t0), 'pings': len(pings), 'ping_times_s': pings,
                'gaps_s': gaps, 'closed': closed})
    await ws.close()
    return res


async def main():
    out, duration, urls = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
    results = await asyncio.gather(*(watch(n, u, duration) for n, u in enumerate(urls)))
    with open(out, 'w') as f:
        json.dump({'measured_at': int(time.time()), 'duration_s': duration, 'results': results}, f, indent=1)
    for r in results:
        print(json.dumps({k: v for k, v in r.items() if k != 'ping_times_s'}))


if __name__ == '__main__':
    asyncio.run(main())
