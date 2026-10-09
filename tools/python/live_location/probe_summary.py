"""Prints a compact table from relay_probe.py JSON output(s)."""

import json
import sys


def yn(v):
    return {True: 'Y', False: 'n', None: '-'}.get(v, str(v))


def ok(r):
    if not isinstance(r, dict):
        return '-'
    if r.get('ok') is True:
        return 'OK'
    m = (r.get('msg') or '').split(':')[0]
    return m or ('TO' if r.get('ok') is None else 'n')


rows = []
for path in sys.argv[1:]:
    for r in json.load(open(path))['results']:
        info = r.get('info', {})
        name = r['url'].replace('wss://', '')
        if 'connect_error' in r:
            rows.append((name, 'CONNECT FAIL: ' + r['connect_error'][:60]))
            continue
        soft = (info.get('software') or '?').split('/')[-1].replace('.git', '')[:16]
        limits = (('A', info.get('auth_required')), ('$', info.get('payment_required')),
                  ('W', info.get('restricted_writes')), ('P', info.get('min_pow_difficulty')))
        flags = ''.join(c for c, f in limits if f)
        nip40 = 40 in (info.get('supported_nips') or [])
        live = r.get('live', {})
        eph = r.get('eph_live', {})
        rep = r.get('replace', {})
        rate1 = r.get('rate_1s', {})
        rate2 = r.get('rate_200ms', {})
        rows.append((name, '%-16s %-4s nip40=%s conn=%4sms addr=%-12s stored=%s live=%s(%sms) replace=%s oldById=%s '
                     'eph=%s(%sms) ephStored=%s ephMute=%-10s expShort=%s expPast=%-10s delA=%s/%s a50=%s '
                     'r1s=%s/%s r200=%s/%s %s %s' % (
                         soft, flags, yn(nip40), r.get('connect_ms'), ok(r.get('addr')),
                         yn(r.get('stored', {}).get('served')), yn(live.get('forwarded')), live.get('latency_ms'),
                         yn(rep.get('latest_only')), yn(rep.get('old_served_by_id')),
                         yn(eph.get('forwarded')), eph.get('latency_ms'), yn(eph.get('served_from_storage_after')),
                         ok(r.get('eph_mute')),
                         ('served' if r.get('exp_short', {}).get('served_after_expiry') else 'hidden'),
                         ok(r.get('exp_past')),
                         ok(r.get('del_a', {}).get('publish')), ('kept' if r.get('del_a', {}).get('still_served')
                                                                 else 'gone'),
                         yn(r.get('authors50', {}).get('accepted')),
                         rate1.get('refused'), rate1.get('sent'), rate2.get('refused'), rate2.get('sent'),
                         (rate1.get('messages') or []) + (rate2.get('messages') or []),
                         ('ERR ' + r['error'][:80]) if 'error' in r else '')))
for name, text in rows:
    print('%-26s %s' % (name, text))
