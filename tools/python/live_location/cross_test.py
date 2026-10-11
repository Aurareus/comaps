"""Cross-implementation test: the C++ core (live_location_peer) and this reference implementation (peer.py)
pair, share and revoke with each other over a local strfry, through real WebSockets.

  Alice   the C++ peer
  Bob     a Python peer that joins Alice's invite, follows her, and later shares with her
  Carol   a Python peer that invites Alice, follows her, and is then removed from her share

Usage: cross_test.py PATH/TO/live_location_peer PATH/TO/strfry [STRFRY_CONFIG]
"""

import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peer import Peer, log  # noqa: E402

failures = 0
checks = 0


def check(cond, what):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        log('FAIL:', what)
    else:
        log('ok:', what)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Strfry:
    def __init__(self, binary, tmp, base_config=None):
        self.port = free_port()
        os.makedirs(os.path.join(tmp, 'db'))
        lines = ['db = "%s/"' % os.path.join(tmp, 'db'),
                 'relay {', '  bind = "127.0.0.1"', '  port = %d' % self.port, '}']
        config = os.path.join(tmp, 'strfry.conf')
        if base_config:
            text = open(base_config).read()
            text = text.replace('port = 7777', 'port = %d' % self.port)
            text = re.sub(r'db = "[^"]*"', 'db = "%s/"' % os.path.join(tmp, 'db'), text)
            open(config, 'w').write(text)
        else:
            open(config, 'w').write('\n'.join(lines) + '\n')
        self.log = open(os.path.join(tmp, 'strfry.log'), 'w')
        self.proc = subprocess.Popen([binary, '--config=' + config, 'relay'], stdout=self.log,
                                     stderr=subprocess.STDOUT)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        self.url = 'ws://127.0.0.1:%d' % self.port

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)


class CppPeer:
    """The C++ peer: line commands in, one JSON event per line out."""

    def __init__(self, binary, name, url, tmp):
        self.name = name
        self.all = []
        self.cv = threading.Condition()
        self.proc = subprocess.Popen([binary, '--state', os.path.join(tmp, name + '.dat')], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=open(os.path.join(tmp, name + '.log'), 'w'),
                                     text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        self.cmd('name ' + name)
        self.cmd('relays ' + url)

    def _read(self):
        for line in self.proc.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            with self.cv:
                self.all.append(ev)
                self.cv.notify_all()

    def mark(self):
        with self.cv:
            return len(self.all)

    def wait(self, pred, start=0, timeout=30):
        """The first event at or after `start` that matches; None on timeout."""
        deadline = time.time() + timeout
        with self.cv:
            i = start
            while True:
                while i < len(self.all):
                    if pred(self.all[i]):
                        return self.all[i]
                    i += 1
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self.cv.wait(remaining)

    def cmd(self, line):
        start = self.mark()
        self.proc.stdin.write(line + '\n')
        self.proc.stdin.flush()
        result = self.wait(lambda e: e['event'] == 'result' and e['command'] == line.split()[0], start)
        if result is None or not result['ok']:
            raise RuntimeError('%s: %s failed' % (self.name, line))
        return start

    async def await_event(self, pred, start=0, timeout=30):
        return await asyncio.to_thread(self.wait, pred, start, timeout)

    def close(self):
        try:
            self.proc.stdin.write('quit\n')
            self.proc.stdin.flush()
            self.proc.wait(10)
        except Exception:
            self.proc.kill()


def contact(event, name):
    for c in event.get('contacts', []):
        if c['name'] == name:
            return c
    return None


def position(event, name):
    for p in event.get('positions', []):
        if p['name'] == name:
            return p
    return None


async def scenario(alice, bob, carol):
    alice.cmd('foreground on')

    # 1. Alice (C++) invites, Bob (Python) joins.
    m = alice.cmd('invite qr')
    invite = await alice.await_event(lambda e: e['event'] == 'pairing' and e['link'], m)
    joined = asyncio.ensure_future(bob.join(invite['link'], timeout=60))
    shown = await alice.await_event(lambda e: e['event'] == 'pairing' and e['stage'] == 'CompareCode', m)
    check(shown is not None and shown['peer'] == 'Bob', 'C++ inviter shows the Python joiner\'s name')
    m = alice.cmd('decide %s accept compared' % shown['id'])
    name = await asyncio.wait_for(joined, 60)
    check(name == 'Alice' and bob.contacts['Alice'].sas == shown['sas'], 'both show the same code: ' + shown['sas'])
    confirmed = await alice.await_event(lambda e: e['event'] == 'contacts' and contact(e, 'Bob') and
                                        not contact(e, 'Bob')['waiting'], m)
    check(confirmed is not None, 'the Python joiner\'s confirmation reached the C++ inviter')

    # 2. Carol (Python) invites, Alice (C++) joins.
    link = asyncio.get_running_loop().create_future()
    invited = asyncio.ensure_future(carol.invite(False, lambda name, sas: True, link.set_result, timeout=60))
    m = alice.cmd('open ' + await asyncio.wait_for(link, 10))
    shown = await alice.await_event(lambda e: e['event'] == 'pairing' and e['stage'] == 'CompareCode', m)
    check(shown is not None, 'the C++ joiner shows a code')
    alice.cmd('confirm %s match' % shown['id'])
    await asyncio.wait_for(invited, 60)
    connected = await alice.await_event(lambda e: e['event'] == 'pairing' and e['stage'] == 'Connected', m)
    check(connected is not None and connected['peer'] == 'Carol' and carol.contacts['Alice'].sas == shown['sas'],
          'C++ joiner and Python inviter connected with the same code')

    # 3. Alice shares with both; the Python peers follow and ask for live updates.
    seen = {'Bob': [], 'Carol': []}
    following = [asyncio.ensure_future(bob.follow(900, on_position=lambda n, b: seen['Bob'].append(b))),
                 asyncio.ensure_future(carol.follow(900, on_position=lambda n, b: seen['Carol'].append(b)))]
    await asyncio.sleep(2)
    m = alice.cmd('share Bob Carol')
    alice.cmd('fix 52.5200066 13.404954 8')

    async def until(cond, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline and not cond():
            await asyncio.sleep(0.2)
        return cond()

    check(await until(lambda: any(abs(b['lat'] - 52.5200066) < 1e-9 for b in seen['Bob']) and
                      any(abs(b['lat'] - 52.5200066) < 1e-9 for b in seen['Carol']), 30),
          'both Python followers decrypt the C++ sharer\'s position')
    live = await alice.await_event(lambda e: e['event'] == 'location' and e['mode'] == 'Live', m, 90)
    check(live is not None, 'Python watch signals make the C++ sharer live')

    # 4. Alice removes Carol: Bob follows the new stream, Carol cannot read it.
    removed_at = time.time()
    alice.cmd('change Bob')
    check(await until(lambda: 'Alice' in carol.removed_at, 30), 'Carol learns she was removed')
    await asyncio.sleep(1)
    bob_count = len(seen['Bob'])
    for _ in range(40):  # the new stream stays silent for 30 to 120 s, then publishes the next fix
        alice.cmd('fix 52.5201 13.4050 8')
        if await until(lambda: len(seen['Bob']) > bob_count and abs(seen['Bob'][-1]['lat'] - 52.5201) < 1e-9, 5):
            break
    check(abs(seen['Bob'][-1]['lat'] - 52.5201) < 1e-9, 'Bob follows Alice\'s new stream (%.0f s after the removal)'
          % (time.time() - removed_at))
    await carol.probe('Alice')
    probe = carol.probe_results.get('Alice', {'events': 0, 'decrypted': 0})
    check(probe['events'] > 0 and probe['decrypted'] == 0,
          'Carol\'s old key opens none of the %d events published after her removal' % probe['events'])
    check(not any(abs(b['lat'] - 52.5201) < 1e-9 for b in seen['Carol']), 'Carol never saw the new position')

    # 5. Bob (Python) shares with Alice (C++).
    m = alice.mark()
    sharing = asyncio.ensure_future(bob.share(['Alice'], 600, 48.8566, 2.3522))
    shown = await alice.await_event(lambda e: e['event'] == 'positions' and position(e, 'Bob') and
                                    abs(position(e, 'Bob')['lat'] - 48.8566) < 1e-9, m, 60)
    check(shown is not None, 'the C++ viewer decrypts the Python sharer\'s position')
    sharing.cancel()

    # 6. Alice stops: Bob sees it.
    alice.cmd('stop')
    check(await until(lambda: 'Alice' in bob.removed_at, 30), 'the Python follower sees the C++ sharer stop')
    for task in following:
        task.cancel()


async def main():
    binary, strfry = sys.argv[1], sys.argv[2]
    base_config = sys.argv[3] if len(sys.argv) > 3 else None
    tmp = tempfile.mkdtemp(prefix='nll_cross_')
    relay = Strfry(strfry, tmp, base_config)
    log('strfry on', relay.url, '- logs in', tmp)
    alice = CppPeer(binary, 'Alice', relay.url, tmp)
    bob = Peer(os.path.join(tmp, 'bob.json'), 'Bob', [relay.url])
    carol = Peer(os.path.join(tmp, 'carol.json'), 'Carol', [relay.url])
    try:
        await scenario(alice, bob, carol)
    except Exception as e:
        check(False, 'scenario raised %r' % e)
    finally:
        alice.close()
        await bob.net.close()
        await carol.net.close()
        relay.stop()
    print('%d checks, %d failures' % (checks, failures))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    asyncio.run(main())
