"""Records the C++ core's views as the Android app receives them, for the SDK's JVM tests of the Java
parsers (android/sdk/src/test/.../livelocation/LiveLocationModelsTest.java).

Two C++ peers pair over a local strfry, one shares with the other, and every kind of event is
written as one JSON object per line: {"name": ..., "event": <the view>}.

Usage: view_fixtures.py PATH/TO/live_location_peer PATH/TO/strfry OUTPUT.jsonl [STRFRY_CONFIG]
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cross_test import CppPeer, Strfry  # noqa: E402

# Nothing listens there: a relay that is not the user's own, to make the core ask for consent.
OTHER_RELAY = 'ws://127.0.0.1:9'


def main():
    binary, strfry, output = sys.argv[1], sys.argv[2], sys.argv[3]
    base_config = sys.argv[4] if len(sys.argv) > 4 else None
    tmp = tempfile.mkdtemp(prefix='nll_views_')
    relay = Strfry(strfry, tmp, base_config)
    alice = CppPeer(binary, 'Alice', relay.url, tmp)
    bob = CppPeer(binary, 'Bob', relay.url, tmp)
    carol = CppPeer(binary, 'Carol', relay.url, tmp)
    views = []

    def record(name, event):
        if event is None:
            raise RuntimeError('no event for ' + name)
        views.append({'name': name, 'event': event})

    def is_pairing(stage):
        return lambda e: e['event'] == 'pairing' and e['stage'] == stage

    try:
        alice.cmd('foreground on')
        bob.cmd('foreground on')

        # Bob invites by link, Alice joins.
        m = bob.cmd('invite link')
        invite = bob.wait(lambda e: e['event'] == 'pairing' and e['link'], m)
        record('pairing_inviter_link', invite)
        m = alice.cmd('open ' + invite['link'])
        record('pairing_joiner_waiting', alice.wait(is_pairing('Waiting'), m))
        joiner = alice.wait(is_pairing('CompareCode'), m, 60)
        record('pairing_joiner_compare', joiner)
        inviter = bob.wait(is_pairing('CompareCode'), 0, 60)
        record('pairing_inviter_compare', inviter)
        bob.cmd('decide %s accept compared' % inviter['id'])
        alice.cmd('confirm %s match' % joiner['id'])
        record('pairing_inviter_connected', bob.wait(is_pairing('Connected'), 0, 60))
        record('pairing_joiner_connected', alice.wait(is_pairing('Connected'), 0, 60))

        # Carol's invite names a relay that Alice has not allowed.
        carol.cmd('relays %s %s' % (relay.url, OTHER_RELAY))
        m = carol.cmd('invite qr')
        qr = carol.wait(lambda e: e['event'] == 'pairing' and e['link'], m)
        record('pairing_inviter_qr', qr)
        m = alice.cmd('open ' + qr['link'])
        record('pairing_needs_consent', alice.wait(is_pairing('NeedsConsent'), m))
        carol.cmd('cancel %s' % qr['id'])

        # Bob's first relay, the one live updates need, is one Alice has not allowed: she is asked
        # about it, and sees live updates off until she allows it. He changes his relays while her
        # CoMaps is closed, so she has not picked them up; once open, it answers through them.
        if bob.wait(lambda e: e['event'] == 'contacts' and e['contacts'] and not e['contacts'][0]['waiting'],
                    0, 60) is None:
            raise RuntimeError("no confirmation from Alice")
        alice.cmd('foreground off')
        m = bob.cmd('relays %s %s' % (OTHER_RELAY, relay.url))
        record('contacts_not_moved', bob.wait(
            lambda e: e['event'] == 'contacts' and e['contacts'] and e['contacts'][0]['not_moved'], m))
        m = bob.mark()
        alice.cmd('foreground on')
        if bob.wait(lambda e: e['event'] == 'contacts' and not e['contacts'][0]['not_moved'], m, 60) is None:
            raise RuntimeError('no answer from Alice')
        m_alice = alice.mark()
        m = bob.cmd('share Alice')
        bob.cmd('fix 52.5200066 13.404954 8')
        record('sharing_active', bob.wait(lambda e: e['event'] == 'sharing' and e['active'], m))
        record('location_idle', bob.wait(lambda e: e['event'] == 'location' and e['mode'] == 'Idle', m))
        record('positions', alice.wait(lambda e: e['event'] == 'positions' and e['positions'], m_alice, 60))
        record('contacts_viewer', alice.wait(
            lambda e: e['event'] == 'contacts' and e['contacts'] and
            e['contacts'][0].get('shares_with_me') is not None, m_alice, 60))
        record('consent_live_updates', alice.wait(lambda e: e['event'] == 'consent', m_alice, 60))
        record('location_live', bob.wait(lambda e: e['event'] == 'location' and e['mode'] == 'Live', m, 90))
        m = bob.cmd('contacts')
        record('contacts_sharer', bob.wait(lambda e: e['event'] == 'contacts', m))

        alice.cmd('consent %s allow Bob' % OTHER_RELAY)
        m = alice.cmd('settings')
        record('settings', alice.wait(lambda e: e['event'] == 'settings', m))

        m = bob.cmd('stop')
        record('sharing_stopped', bob.wait(lambda e: e['event'] == 'sharing' and not e['active'], m))
    finally:
        for peer in (alice, bob, carol):
            peer.close()
        relay.stop()

    with open(output, 'w') as out:
        for view in views:
            out.write(json.dumps(view, ensure_ascii=False, sort_keys=True) + '\n')
    print('%d views written to %s' % (len(views), output))


if __name__ == '__main__':
    main()
