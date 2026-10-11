"""Empirical relay behaviour probe for the live-location design.

For each relay it answers, with fresh random keys and no AUTH / PoW / payment:
  info       NIP-11 document: supported NIPs, limitations (auth/payment/pow/restricted writes)
  connect    WebSocket connect time
  addr       addressable kind accepted (with empty d tag and NIP-40 expiration)? OK latency
  stored     stored addressable event served to a second connection?
  replace    newer version replaces older one (old id no longer served)?
  live       addressable event forwarded live to an open subscription? latency
  eph_live   ephemeral kind forwarded to an open subscription? latency
  eph_mute   ephemeral kind with no listener: OK / mute / error message
  exp_short  event expiring in a few seconds stops being served after expiry (NIP-40)?
  exp_past   already-expired event rejected at ingest (NIP-40)?
  del_a      NIP-09 deletion by `a` tag removes the addressable event?
  authors50  REQ with 50 authors accepted?
  rate       burst of N events from one key at 1 s and 0.2 s spacing: first refusal and its message

Kept deliberately small (a few dozen events per relay) to be a polite client.
Usage: relay_probe.py OUT.json wss://relay1 [wss://relay2 ...]
"""

import asyncio
import json
import os
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from websockets.asyncio.client import connect  # noqa: E402

from nll import primitives as p  # noqa: E402
from nll.nostr import Event  # noqa: E402

KIND_ADDR = 30484
KIND_EPH = 20484
TIMEOUT = 10.0


def new_key():
    while True:
        sk = os.urandom(32)
        if p.secp_is_valid_secret(sk):
            return sk


def make_event(sk, kind, content, tags=None, created_at=None):
    ev = Event(pubkey=p.secp_xonly_pub(sk).hex(), created_at=created_at or int(time.time()), kind=kind,
               tags=tags or [], content=content)
    return ev.sign(sk, os.urandom(32))


def random_content():
    # Same shape as real traffic: base64 of a NIP-44-sized blob (99 bytes -> 132 chars).
    return p.b64encode(b'\x02' + os.urandom(98))


def ssl_context(url):
    if not url.startswith('wss://'):
        return None
    ctx = ssl.create_default_context()
    cafile = os.environ.get('SSL_CERT_FILE')
    if cafile:
        ctx.load_verify_locations(cafile)
    return ctx


class Conn:
    """One relay connection with a message dispatcher."""

    def __init__(self, url):
        self.url = url
        self.ws = None
        self.queue = asyncio.Queue()
        self.reader = None
        self.notices = []
        self.auth_challenge = None

    async def open(self):
        t0 = time.monotonic()
        self.ws = await connect(self.url, ssl=ssl_context(self.url), open_timeout=TIMEOUT, max_size=2 ** 22,
                                proxy=True if self.url.startswith('wss://') else None)
        self.reader = asyncio.create_task(self._read())
        return time.monotonic() - t0

    async def _read(self):
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if msg and msg[0] == 'NOTICE':
                    self.notices.append(msg[1] if len(msg) > 1 else '')
                elif msg and msg[0] == 'AUTH':
                    self.auth_challenge = msg[1] if len(msg) > 1 else ''
                await self.queue.put((time.monotonic(), msg))
        except Exception as e:  # connection closed
            await self.queue.put((time.monotonic(), ['__CLOSED__', repr(e)]))

    async def send(self, msg):
        await self.ws.send(json.dumps(msg, separators=(',', ':')))

    async def wait_for(self, pred, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, None
            try:
                t, msg = await asyncio.wait_for(self.queue.get(), remaining)
            except asyncio.TimeoutError:
                return None, None
            if msg and msg[0] == '__CLOSED__':
                return t, msg
            if pred(msg):
                return t, msg

    async def publish(self, ev, timeout=TIMEOUT):
        t0 = time.monotonic()
        await self.send(['EVENT', ev.to_dict()])
        t, msg = await self.wait_for(lambda m: m[0] in ('OK',) and len(m) >= 3 and m[1] == ev.id, timeout)
        if msg is None:
            return {'ok': None, 'msg': 'timeout'}
        if msg[0] == '__CLOSED__':
            return {'ok': None, 'msg': 'closed: ' + msg[1]}
        return {'ok': bool(msg[2]), 'msg': msg[3] if len(msg) > 3 else '', 'latency_ms': round((t - t0) * 1000)}

    async def query(self, sub_id, flt, timeout=TIMEOUT):
        """REQ until EOSE; returns (events, closed_message or None)."""
        def mine(m):
            return m[0] in ('EVENT', 'EOSE', 'CLOSED') and len(m) > 1 and m[1] == sub_id

        await self.send(['REQ', sub_id, flt])
        events = []
        while True:
            t, msg = await self.wait_for(mine, timeout)
            if msg is None:
                return events, 'timeout'
            if msg[0] == '__CLOSED__':
                return events, 'closed'
            if msg[0] == 'EVENT':
                events.append(msg[2])
            elif msg[0] == 'EOSE':
                return events, None
            else:
                return events, 'CLOSED: ' + (msg[2] if len(msg) > 2 else '')

    async def close_sub(self, sub_id):
        await self.send(['CLOSE', sub_id])

    async def close(self):
        if self.reader:
            self.reader.cancel()
        if self.ws:
            await self.ws.close()


def fetch_nip11(url):
    http = 'https://' + url[len('wss://'):] if url.startswith('wss://') else 'http://' + url[len('ws://'):]
    req = urllib.request.Request(http, headers={'Accept': 'application/nostr+json'})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            d = json.loads(r.read().decode('utf-8'))
    except Exception as e:
        return {'error': repr(e)[:200]}
    lim = d.get('limitation') or {}
    return {
        'software': d.get('software'), 'version': d.get('version'),
        'supported_nips': d.get('supported_nips'),
        'auth_required': lim.get('auth_required'), 'payment_required': lim.get('payment_required'),
        'restricted_writes': lim.get('restricted_writes'), 'min_pow_difficulty': lim.get('min_pow_difficulty'),
        'max_message_length': lim.get('max_message_length'), 'max_subscriptions': lim.get('max_subscriptions'),
        'max_limit': lim.get('max_limit'), 'max_event_tags': lim.get('max_event_tags'),
        'created_at_lower_limit': lim.get('created_at_lower_limit'),
        'created_at_upper_limit': lim.get('created_at_upper_limit'),
        'retention': d.get('retention'),
    }


async def probe(url, rate_burst=10):
    res = {'url': url, 'info': await asyncio.to_thread(fetch_nip11, url)}
    pub, sub = Conn(url), Conn(url)
    try:
        res['connect_ms'] = round(await pub.open() * 1000)
        await sub.open()
    except Exception as e:
        res['connect_error'] = repr(e)[:300]
        return res
    try:
        now = int(time.time())
        sk = new_key()
        pk = p.secp_xonly_pub(sk).hex()

        # Addressable event with empty d tag and an expiration 10 minutes ahead.
        ev1 = make_event(sk, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(now + 600)]])
        res['addr'] = await pub.publish(ev1)

        events, err = await sub.query('s1', {'kinds': [KIND_ADDR], 'authors': [pk]})
        res['stored'] = {'served': [e['id'] for e in events] == [ev1.id], 'n': len(events), 'err': err}

        # Live forwarding of an addressable replacement to the open subscription s1.
        ev2 = make_event(sk, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(now + 600)]],
                         created_at=now + 1)
        t_send = time.monotonic()
        res['replace_publish'] = await pub.publish(ev2)
        t, msg = await sub.wait_for(lambda m: m[0] == 'EVENT' and m[1] == 's1' and m[2]['id'] == ev2.id)
        res['live'] = {'forwarded': msg is not None and msg[0] == 'EVENT',
                       'latency_ms': round((t - t_send) * 1000) if msg else None}
        await sub.close_sub('s1')

        events, err = await sub.query('s2', {'kinds': [KIND_ADDR], 'authors': [pk]})
        ids = [e['id'] for e in events]
        res['replace'] = {'latest_only': ids == [ev2.id], 'ids_served': len(ids), 'err': err}
        events, err = await sub.query('s3', {'ids': [ev1.id]})
        res['replace']['old_served_by_id'] = len(events) > 0
        await sub.close_sub('s2')
        await sub.close_sub('s3')

        # Ephemeral forwarded to an open subscription.
        sk_e = new_key()
        pk_e = p.secp_xonly_pub(sk_e).hex()
        await sub.send(['REQ', 's4', {'kinds': [KIND_EPH], 'authors': [pk_e]}])
        await sub.wait_for(lambda m: m[0] in ('EOSE', 'CLOSED') and m[1] == 's4')
        eph = make_event(sk_e, KIND_EPH, random_content())
        t_send = time.monotonic()
        ok = await pub.publish(eph)
        t, msg = await sub.wait_for(lambda m: m[0] == 'EVENT' and m[1] == 's4' and m[2]['id'] == eph.id)
        res['eph_live'] = {'publish': ok, 'forwarded': msg is not None and msg[0] == 'EVENT',
                           'latency_ms': round((t - t_send) * 1000) if msg else None}
        await sub.close_sub('s4')
        events, err = await sub.query('s5', {'ids': [eph.id]})
        res['eph_live']['served_from_storage_after'] = len(events) > 0

        # Ephemeral without listener.
        res['eph_mute'] = await pub.publish(make_event(new_key(), KIND_EPH, random_content()))

        # NIP-40: short expiry stops being served; already-expired is rejected at ingest.
        sk_x = new_key()
        pk_x = p.secp_xonly_pub(sk_x).hex()
        evx = make_event(sk_x, KIND_ADDR, random_content(), [['d', ''], ['expiration', str(int(time.time()) + 4)]])
        pub_ok = await pub.publish(evx)
        await asyncio.sleep(8)
        events, err = await sub.query('s6', {'kinds': [KIND_ADDR], 'authors': [pk_x]})
        res['exp_short'] = {'publish': pub_ok, 'served_after_expiry': len(events) > 0, 'err': err}
        res['exp_past'] = await pub.publish(make_event(new_key(), KIND_ADDR, random_content(),
                                                       [['d', ''], ['expiration', str(int(time.time()) - 60)]]))

        # NIP-09 deletion of the addressable event by `a` tag.
        # Deletion requests are kept by relays indefinitely (NIP-09), so this one carries an expiry.
        dele = make_event(sk, 5, '', [['a', '%d:%s:' % (KIND_ADDR, pk)], ['k', str(KIND_ADDR)],
                                      ['expiration', str(int(time.time()) + 600)]],
                          created_at=int(time.time()) + 2)
        res['del_a'] = {'publish': await pub.publish(dele)}
        events, err = await sub.query('s7', {'kinds': [KIND_ADDR], 'authors': [pk]})
        res['del_a']['still_served'] = len(events) > 0
        events, err = await sub.query('s8', {'kinds': [5], 'authors': [pk]})
        res['del_a']['deletion_event_served'] = len(events) > 0

        # Subscription with 50 authors.
        events, err = await sub.query('s9', {'kinds': [KIND_ADDR],
                                             'authors': [p.secp_xonly_pub(new_key()).hex() for _ in range(49)] + [pk]})
        res['authors50'] = {'accepted': err is None, 'err': err}

        # Rate: burst of addressable updates from one key, 1 s apart, then 0.2 s apart.
        for label, gap in (('rate_1s', 1.0), ('rate_200ms', 0.2)):
            sk_r = new_key()
            results = []
            for i in range(rate_burst):
                tags = [['d', ''], ['expiration', str(int(time.time()) + 300)]]
                ev = make_event(sk_r, KIND_ADDR, random_content(), tags,
                                created_at=int(time.time()) + i)
                r = await pub.publish(ev)
                results.append(r)
                await asyncio.sleep(gap)
            refused = [i for i, r in enumerate(results) if not r.get('ok')]
            res[label] = {'sent': rate_burst, 'refused': len(refused),
                          'first_refused_at': refused[0] if refused else None,
                          'messages': sorted({r.get('msg', '') for r in results if not r.get('ok')})}
        res['auth_challenge'] = pub.auth_challenge is not None
        res['notices'] = (pub.notices + sub.notices)[:5]
    except Exception as e:
        res['error'] = repr(e)[:300]
    finally:
        await pub.close()
        await sub.close()
    return res


async def main():
    out = sys.argv[1]
    urls = sys.argv[2:]
    results = await asyncio.gather(*(probe(u) for u in urls))
    with open(out, 'w') as f:
        json.dump({'probed_at': int(time.time()), 'results': results}, f, indent=1)
    for r in results:
        print(json.dumps(r)[:2000])


if __name__ == '__main__':
    asyncio.run(main())
