"""A test peer for live location (NLL v1), on the reference implementation.

It pairs with a phone through a real invite, follows the phone's share, and checks revocation: once the
phone stops sharing with it or removes it, it keeps the old stream key and tries it on every event
published to the phone's relays afterwards, logging how many it could decrypt (it must be none).

  peer.py --state bob.json --name Bob join 'comaps://live/pair#...'
  peer.py --state alice.json --name Alice invite [--link] [--accept]
  peer.py --state bob.json follow [--minutes 30] [--no-live]
  peer.py --state alice.json share --to Bob [--minutes 30] [--lat 52.52 --lon 13.405] [--walk]

Relays default to the design doc's (D5); --relays sets this peer's own list. The state file holds secret
keys in the clear: this is a test tool. Positions are never written to it.
"""

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from websockets.asyncio.client import connect  # noqa: E402

from nll import protocol as P  # noqa: E402
from nll import primitives as p  # noqa: E402
from nll.nostr import Event  # noqa: E402
from relay_probe import ssl_context  # noqa: E402


def now():
    return int(time.time())


def log(*args):
    print(time.strftime('%H:%M:%S'), *args, flush=True)


# --- Relays ---------------------------------------------------------------------------------------

class Conn:
    """One WebSocket to one relay, carrying one scope (spec §11)."""

    def __init__(self, url):
        self.url = url
        self.ws = None
        self.subs = {}       # sub id -> callback(event dict)
        self.eoses = {}      # sub id -> callback()
        self.oks = {}        # event id -> future
        self.reader = None

    async def open(self):
        self.ws = await connect(self.url, ssl=ssl_context(self.url), open_timeout=10, max_size=2 ** 22,
                                proxy=True if self.url.startswith('wss://') else None)
        self.reader = asyncio.create_task(self._read())

    async def _read(self):
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, list) or len(msg) < 2:
                    continue
                if msg[0] == 'EVENT' and len(msg) >= 3 and msg[1] in self.subs:
                    self.subs[msg[1]](msg[2])
                elif msg[0] == 'OK' and len(msg) >= 3 and msg[1] in self.oks:
                    fut = self.oks.pop(msg[1])
                    if not fut.done():
                        fut.set_result(bool(msg[2]))
                elif msg[0] == 'EOSE' and msg[1] in self.eoses:
                    self.eoses.pop(msg[1])()
        except Exception:
            pass
        for fut in self.oks.values():
            if not fut.done():
                fut.set_result(False)

    async def send(self, msg):
        await self.ws.send(json.dumps(msg, separators=(',', ':'), ensure_ascii=False))

    async def publish(self, ev, timeout=10):
        fut = asyncio.get_running_loop().create_future()
        self.oks[ev.id] = fut
        await self.send(['EVENT', ev.to_dict()])
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return False

    async def close(self):
        if self.ws is not None:
            await self.ws.close()
        if self.reader is not None:
            self.reader.cancel()


def matches(flt, ev):
    """NIP-01 filter matching, for the fields NLL uses."""
    if 'kinds' in flt and ev.kind not in flt['kinds']:
        return False
    if 'authors' in flt and ev.pubkey not in flt['authors']:
        return False
    if 'since' in flt and ev.created_at < flt['since']:
        return False
    if '#p' in flt and not any(len(t) >= 2 and t[0] == 'p' and t[1] in flt['#p'] for t in ev.tags):
        return False
    return True


class Network:
    """Connections by (relay, scope): a connection never carries keys of two epochs, nor a pairing and a
    channel (spec §11; design doc §21)."""

    def __init__(self):
        self.conns = {}

    async def conn(self, url, scope):
        key = (url, scope)
        if key not in self.conns:
            c = Conn(url)
            await c.open()
            self.conns[key] = c
        return self.conns[key]

    async def publish(self, urls, scope, ev):
        """True once one relay accepted the event."""
        async def one(url):
            try:
                return await (await self.conn(url, scope)).publish(ev)
            except Exception as e:
                log('publish to %s failed: %r' % (url, e))
                return False
        results = await asyncio.gather(*(one(u) for u in urls))
        return any(results)

    async def subscribe(self, urls, scope, filters, on_event, on_eose=None):
        """REQ on every relay, events deduplicated by id. Returns a handle for unsubscribe()."""
        seen = set()
        handle = []

        def deliver(evd):
            # Seen only once verified and asked for: a relay that sends a broken copy first must not
            # hide the intact one another relay delivers (spec §11).
            try:
                ev = Event.from_dict(evd)
                if ev.id in seen or not any(matches(f, ev) for f in filters) or not ev.verify():
                    return
            except Exception:
                return
            seen.add(ev.id)
            try:
                on_event(ev)
            except Exception as e:
                log('event dropped: %r' % e)

        for url in urls:
            try:
                c = await self.conn(url, scope)
            except Exception as e:
                log('cannot reach %s: %r' % (url, e))
                continue
            sub_id = os.urandom(8).hex()   # random per REQ: ids must not link connections
            c.subs[sub_id] = deliver
            if on_eose is not None:
                c.eoses[sub_id] = on_eose
            await c.send(['REQ', sub_id] + filters)
            handle.append((c, sub_id))
        return handle

    async def unsubscribe(self, handle):
        for c, sub_id in handle:
            c.subs.pop(sub_id, None)
            try:
                await c.send(['CLOSE', sub_id])
            except Exception:
                pass

    async def query(self, url, scope, flt, timeout=10):
        """The stored events matching `flt` on one relay."""
        out, done = [], asyncio.Event()
        handle = await self.subscribe([url], scope, [flt], out.append, done.set)
        try:
            await asyncio.wait_for(done.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        await self.unsubscribe(handle)
        return out

    async def close(self):
        for c in self.conns.values():
            await c.close()
        self.conns = {}


def epoch_scope(epoch):
    return 'e%d' % epoch


# --- State ----------------------------------------------------------------------------------------

def contact_to_dict(c):
    return {'name': c.name, 'relays': c.relays, 'out': [c.outgoing.epoch, c.outgoing.chain_key.hex()],
            'in': [c.incoming.epoch, c.incoming.chain_key.hex()], 'sas': c.sas, 'pairing_epoch': c.pairing_epoch,
            'joiner': c.joiner, 'last_seq_in': c.last_seq_in, 'seq_out': c.seq_out,
            'last_created_out': c.last_created_out, 'verified': c.verified, 'flagged': c.flagged,
            'confirmed': c.confirmed}


def contact_from_dict(d):
    c = P.Contact(d['name'], d['relays'], P.Direction(d['out'][0], bytes.fromhex(d['out'][1])),
                  P.Direction(d['in'][0], bytes.fromhex(d['in'][1])), d['sas'])
    for k in ('pairing_epoch', 'joiner', 'last_seq_in', 'seq_out', 'last_created_out', 'verified', 'flagged',
              'confirmed'):
        setattr(c, k, d[k])
    return c


class Peer:
    def __init__(self, state_path, name=None, relays=None, rng=os.urandom):
        self.path = state_path
        self.rng = rng
        self.net = Network()
        state = {}
        if state_path and os.path.exists(state_path):
            with open(state_path) as f:
                state = json.load(f)
        self.name = name or state.get('name', 'Test peer')
        self.relays = P.check_relays(relays or state.get('relays', P.DEFAULT_RELAYS))
        self.decoy_seed = bytes.fromhex(state['decoy_seed']) if 'decoy_seed' in state else rng(32)
        self.contacts = {d['name']: contact_from_dict(d) for d in state.get('contacts', [])}
        self.positions = {}        # name -> last location, in memory only
        self.colors = {}           # name -> the dot colour from its last state, or None
        self.removed_at = {}       # name -> (time, old stream key, old stream pk)
        self.probe_results = {}    # name -> {'events': n, 'decrypted': n}

    def save(self):
        if not self.path:
            return
        state = {'name': self.name, 'relays': self.relays, 'decoy_seed': self.decoy_seed.hex(),
                 'contacts': [contact_to_dict(c) for c in self.contacts.values()]}
        tmp = self.path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f, indent=1)
        os.replace(tmp, self.path)

    def add_contact(self, c):
        name, n = c.name, 2
        while name in self.contacts:
            name, n = '%s %d' % (c.name, n), n + 1
        c.name = name
        self.contacts[name] = c
        self.save()
        return name

    async def publish_state(self, c, ev):
        epoch = max(P.epoch_of(ev.created_at), c.outgoing.epoch)
        return await self.net.publish(c.relays, epoch_scope(epoch), ev)

    def follow_relays(self, c, st, current_state):
        """A state names the contact's current relays (spec §8). When they changed, everything goes there from
        now on, and so does an answer at once: the contact's app learns that this peer has moved (spec §11).
        Unlike the app, this test peer does not ask before using a relay, and does not retry an answer."""
        if st['relays'] == c.relays:
            return
        c.relays = list(st['relays'])
        self.save()
        log('%s moved to %s; answering there' % (c.name, ', '.join(c.relays)))
        asyncio.ensure_future(self.publish_state(c, current_state()))

    # --- Pairing ----------------------------------------------------------------------------------

    async def _pair(self, party, invite, scope, joiner, decide=None, timeout=600):
        """Runs a pairing to its end. Returns the contact's name, or raises."""
        done = asyncio.get_running_loop().create_future()
        held = []
        ipk = invite.ipk.hex()

        def finish(result):
            if not done.done():
                done.set_result(result)

        def on_event(ev):
            try:
                out = party.on_event(ev, self.rng, now())
            except P.PairingAborted as e:
                finish(e)
                return
            except ValueError as e:
                if 'out of order' in str(e):
                    held.append(ev)
                    return
                raise
            if out is None:
                return
            if out.contact is not None:          # the joiner accepted step 3
                name = self.add_contact(out.contact)
                log('connected with %s, code %s' % (name, out.contact.sas))
                asyncio.ensure_future(self.publish_state(out.contact, out.publish))   # its confirmation
                finish(name)
                return
            if out.declined:
                finish(RuntimeError('declined'))
                return
            if out.publish is not None:
                asyncio.ensure_future(self.net.publish(invite.relays, scope, out.publish))
            if out.show_code is not None:
                log('code %s%s' % (out.show_code['sas'],
                                   (' from %s' % out.show_code['name']) if out.show_code.get('name') else ''))
                if decide is not None:
                    asyncio.ensure_future(decide(out.show_code))
            for e in list(held):
                held.remove(e)
                on_event(e)

        filters = [{'kinds': [P.KIND_STORED], '#p': [ipk]}]
        if joiner:
            filters.append({'kinds': [P.KIND_STORED], 'authors': [ipk]})
        handle = await self.net.subscribe(invite.relays, scope, filters, on_event)
        try:
            result = await asyncio.wait_for(done, timeout)
        finally:
            await self.net.unsubscribe(handle)
        if isinstance(result, Exception):
            raise result
        return result

    async def join(self, link, timeout=600):
        invite = P.Invite.from_link(link)
        joiner = P.Joiner(invite, self.name, self.relays, self.rng, now())
        scope = 'p' + os.urandom(8).hex()
        await self.net.publish(invite.relays, scope, joiner.commit_event(self.rng, now()))
        log('step 0 published; waiting for the inviter')
        return await self._pair(joiner, invite, scope, True, timeout=timeout)

    async def invite(self, by_link=False, accept=None, on_link=None, timeout=600):
        """`accept(name, sas)` decides (default: ask on stdin)."""
        inviter = P.Inviter(self.relays, self.rng, now(), lifetime=86400 if by_link else 600)
        link = inviter.invite.link()
        log('invite: %s' % link)
        if on_link is not None:
            on_link(link)
        scope = 'p' + os.urandom(8).hex()
        result = {}

        async def decide(show):
            ok = accept(show['name'], show['sas']) if accept else \
                input('%s, code %s: connect? [y/N] ' % (show['name'], show['sas'])).strip().lower() == 'y'
            out = inviter.decide(ok, self.name, self.relays, self.rng, now())
            await self.net.publish(inviter.invite.relays, scope, out.publish)
            if out.contact is not None:
                result['name'] = self.add_contact(out.contact)
                log('connected with %s (waiting for its confirmation)' % result['name'])
            finished.set()

        finished = asyncio.Event()
        task = asyncio.ensure_future(self._pair(inviter, inviter.invite, scope, False, decide, timeout))
        await asyncio.wait([task, asyncio.ensure_future(finished.wait())], timeout=timeout,
                           return_when=asyncio.FIRST_COMPLETED)
        if task.done() and task.exception() is not None:
            raise task.exception()
        task.cancel()
        if 'name' not in result:
            raise RuntimeError('not connected')
        return result['name']

    # --- Following --------------------------------------------------------------------------------

    async def follow(self, seconds, live=True, probe=True, on_position=None):
        """Reads the inbox for states, follows granted streams, sends watch signals, and after a removal
        tries the old stream key on everything that follows."""
        views = {name: P.Following() for name in self.contacts}
        streams = {}
        epoch = P.epoch_of(now())
        scope = epoch_scope(epoch)
        end = time.time() + seconds

        def on_stream(name, ev):
            body = views[name].on_stream(ev, now())
            if body is None:
                return
            if body['t'] == 'loc':
                self.positions[name] = body
                log('%s at %.6f, %.6f (±%s m)' % (name, body['lat'], body['lon'], body['acc']))
                if on_position is not None:
                    on_position(name, body)
            else:
                log('%s: the stream ended' % name)

        async def follow_stream(name, grant, relays):
            if name in streams:
                await self.net.unsubscribe(streams.pop(name))
            flt = {'kinds': [P.KIND_STORED], 'authors': [grant['pk']]}
            streams[name] = await self.net.subscribe(relays, scope, [flt], lambda ev: on_stream(name, ev))

        def on_inbox(ev):
            for name, c in self.contacts.items():
                st = P.read_control(c, ev, now())
                if st is None:
                    continue
                self.save()
                self.follow_relays(c, st, lambda: P.state_event(c, self.relays, None, self.rng, now()))
                old = views[name].grant
                views[name].on_state(st, now())
                self.colors[name] = views[name].color
                grant = views[name].grant
                if grant is not None and (old is None or grant['pk'] != old['pk']):
                    until = time.strftime(' until %H:%M', time.localtime(grant['until'])) if grant['until'] else ''
                    log('%s shares with me%s' % (name, until))
                    asyncio.ensure_future(follow_stream(name, grant, st['relays']))
                    if live:
                        asyncio.ensure_future(self.watch(c))
                elif grant is None and old is not None:
                    log('%s stopped sharing with me, or removed me' % name)
                    self.removed_at[name] = (now(), p.b64decode(old['key']), old['pk'], st['relays'])
                return

        contacts = list(self.contacts.values())
        inbox = await self.net.subscribe(self.relays, scope, P.inbox_filters(contacts, self.decoy_seed, epoch, now()),
                                         on_inbox) if contacts else []
        next_watch = time.time() + 60
        while time.time() < end:
            await asyncio.sleep(1)
            if live and time.time() >= next_watch:
                next_watch = time.time() + 60
                for name, c in self.contacts.items():
                    if views[name].grant is not None:
                        await self.watch(c)
            for name in list(self.removed_at):
                if probe and name not in self.probe_results:
                    self.probe_results[name] = {'events': 0, 'decrypted': 0, 'checked': set()}
                if probe and int(time.time()) % 15 == 0:
                    await self.probe(name)
        await self.net.unsubscribe(inbox)
        for handle in streams.values():
            await self.net.unsubscribe(handle)

    async def watch(self, c):
        ev = P.watch_signal(c, now() + 120, self.rng, now())
        await self.net.publish(c.relays, epoch_scope(max(P.epoch_of(now()), c.outgoing.epoch)), ev)

    async def probe(self, name):
        """After a removal: every event on the sharer's relays since then, tried with the old stream key.
        The old stream's own end is skipped (it is meant to be read)."""
        since, key, old_pk, relays = self.removed_at[name]
        res = self.probe_results[name]
        for url in relays:
            try:
                events = await self.net.query(url, 'probe', {'kinds': [P.KIND_STORED], 'since': since - 5,
                                                             'limit': 500})
            except Exception:
                continue
            for ev in events:
                if ev.id in res['checked'] or ev.pubkey == old_pk:
                    continue
                res['checked'].add(ev.id)
                res['events'] += 1
                try:
                    P.open_sealed(ev.content, key)
                    res['decrypted'] += 1
                    log('PROBE: %s decrypted an event with the old key: %s' % (name, ev.id))
                except Exception:
                    pass
        log('probe %s: %d events published since the removal, %d decrypted with the old key'
            % (name, res['events'], res['decrypted']))

    # --- Sharing ----------------------------------------------------------------------------------

    async def share(self, to, seconds, lat, lon, walk=False, until=0, on_live=None, color=None):
        """Shares a position with the contacts named in `to`: every 5 s while a recipient watches, every
        60 s otherwise. Stops after `seconds`, with the states first and the old stream's end after their
        OKs (spec §9)."""
        recipients = {self.contacts[n]: until for n in to}
        sharer = P.Sharer(self.relays, color)
        epoch = P.epoch_of(now())
        await self._rekey(sharer.start(recipients, self.rng, now()), None)
        live_until = 0
        end = time.time() + seconds

        def on_inbox(ev):
            nonlocal live_until
            for c in recipients:
                st = P.read_control(c, ev, now())
                if st is not None:
                    self.follow_relays(c, st, lambda: sharer.current_state(c, self.rng, now()))
                    return
                w = P.read_signal(c, ev, now())
                if w is not None:
                    if now() >= live_until and on_live is not None:
                        on_live(c.name)
                    live_until = max(live_until, min(w['until'], now() + 120))
                    return

        inbox = await self.net.subscribe(self.relays, epoch_scope(epoch),
                                         P.inbox_filters(list(recipients), self.decoy_seed, epoch, now()), on_inbox)
        last = 0
        step = 0
        try:
            while time.time() < end:
                interval = 5 if now() < live_until else 60
                if time.time() - last >= interval:
                    fix = {'ts': int(time.time() * 1000), 'lat': lat + (0.0001 * step if walk else 0), 'lon': lon,
                           'acc': 5.0}
                    ev = sharer.location(fix, self.rng, now())
                    if ev is not None:
                        await self.net.publish(self.relays, epoch_scope(sharer.stream_epoch), ev)
                        last = time.time()
                        step += 1
                old_epoch = sharer.stream_epoch
                rk = sharer.tick(self.rng, now())
                if rk is not None:
                    await self._rekey(rk, old_epoch)
                    if sharer.stream is None:
                        return
                await asyncio.sleep(1)
            old_epoch = sharer.stream_epoch
            await self._rekey(sharer.stop(self.rng, now()), old_epoch)
        finally:
            await self.net.unsubscribe(inbox)

    async def _rekey(self, rk, old_epoch):
        """The states first; the old stream's end once they have an OK, or after OK_WAIT (spec §9)."""
        jobs = []
        for ev in rk.states:
            for c in self.contacts.values():
                if ev.pubkey == c.outgoing.at(max(P.epoch_of(ev.created_at), c.outgoing.epoch)).pubkey():
                    jobs.append(self.publish_state(c, ev))
        self.save()
        if jobs:
            try:
                await asyncio.wait_for(asyncio.gather(*jobs), P.OK_WAIT)
            except asyncio.TimeoutError:
                pass
        if rk.end is not None:
            await self.net.publish(self.relays, epoch_scope(old_epoch), rk.end)


async def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--state', required=True, help='JSON state file (secret keys in the clear)')
    ap.add_argument('--name', help='this peer\'s name, sent when pairing')
    ap.add_argument('--relays', nargs='+', help='this peer\'s home relays, in order')
    sub = ap.add_subparsers(dest='command', required=True)
    j = sub.add_parser('join')
    j.add_argument('link')
    i = sub.add_parser('invite')
    i.add_argument('--link', action='store_true', help='an invite that lives a day (default: a QR code, 10 min)')
    i.add_argument('--accept', action='store_true', help='connect without asking')
    f = sub.add_parser('follow')
    f.add_argument('--minutes', type=float, default=30)
    f.add_argument('--no-live', action='store_true', help='do not ask for live updates')
    f.add_argument('--no-probe', action='store_true')
    s = sub.add_parser('share')
    s.add_argument('--to', nargs='+', required=True)
    s.add_argument('--minutes', type=float, default=30)
    s.add_argument('--lat', type=float, default=52.5200066)
    s.add_argument('--lon', type=float, default=13.404954)
    s.add_argument('--walk', action='store_true')
    s.add_argument('--color', help='the dot colour viewers are asked to show, e.g. teal (spec §8)')
    args = ap.parse_args()

    peer = Peer(args.state, args.name, args.relays)
    peer.save()
    try:
        if args.command == 'join':
            await peer.join(args.link)
        elif args.command == 'invite':
            await peer.invite(args.link, (lambda name, sas: True) if args.accept else None)
        elif args.command == 'follow':
            await peer.follow(args.minutes * 60, live=not args.no_live, probe=not args.no_probe)
            for name, res in peer.probe_results.items():
                log('summary %s: %d events after the removal, %d decrypted with the old key'
                    % (name, res['events'], res['decrypted']))
        elif args.command == 'share':
            await peer.share(args.to, args.minutes * 60, args.lat, args.lon, args.walk, color=args.color)
    finally:
        await peer.net.close()


if __name__ == '__main__':
    asyncio.run(main())
