"""Generates vectors/profile_cases.json: inputs for the plaintext decoding of spec §5 and §12 item 5,
each with the verdict of this reference implementation. A second implementation must reach the same
verdict on every input (the C++ one does, in live_location_tests).

Hand-written cases cover each rule of the I-JSON profile; the rest are deterministic mutations of valid
plaintexts. Usage: make_profile_cases.py [OUT.json]
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nll import protocol as P  # noqa: E402

KEY = 'f97a7d56758eb3e0b443ab5640ef103a98b8e5e001114ab8692307a996daf680'
PK = '06f878de96f0b336af58bde816e87d2657c64c508b58cd63490252863ea781ef'

BASES = [
    {'t': 'state', 'seq': 7, 'ts': 1760000200, 'relays': ['wss://nos.lol', 'wss://nostr.mom'],
     'share': {'until': 1760003800, 'pk': PK, 'key': '+Xp9VnWOs+C0Q6tWQO8QOpi45eABEUq4aSMHqZba9oA='}},
    {'t': 'loc', 'seq': 1, 'ts': 1760000205000, 'lat': 52.5200066, 'lon': 13.404954, 'acc': 8.0, 'spd': 1.4,
     'brg': 271.0, 'alt': -3.5e-2, 'low': True, 'nav': {'eta': 1760003000, 'dist': 1234.5, 'dest': 'Café €'}},
    {'t': 'end', 'seq': 2, 'ts': 1760000230},
    {'t': 'watch', 'ts': 1760000240, 'until': 1760000360},
    {'t': 'pair2', 'name': 'Zoë 🗺', 'relays': ['ws://127.0.0.1:7777/x']},
    {'t': 'pair3', 'ok': False},
]

HAND = [
    ('minimal object', b'{"t":"x"}'),
    ('padded with spaces', b'{"t":"x"}' + b' ' * 503),
    ('whitespace of all four kinds', b'\t\r\n {"t" : "x"}\n'),
    ('513 bytes', b'{"t":"x"}' + b' ' * 504),
    ('t missing', b'{"seq":1}'),
    ('t not a string', b'{"t":1}'),
    ('top-level array', b'[{"t":"x"}]'),
    ('top-level string', b'"x"'),
    ('top-level number', b'5'),
    ('empty', b''),
    ('only spaces', b'   '),
    ('trailing garbage', b'{"t":"x"} x'),
    ('two values', b'{"t":"x"}{"t":"x"}'),
    ('trailing comma in object', b'{"t":"x",}'),
    ('trailing comma in array', b'{"t":"x","a":[1,]}'),
    ('single quotes', b"{'t':'x'}"),
    ('comment', b'{"t":"x"/* c */}'),
    ('NaN', b'{"t":"x","a":NaN}'),
    ('Infinity', b'{"t":"x","a":Infinity}'),
    ('-Infinity', b'{"t":"x","a":-Infinity}'),
    ('overflowing number', b'{"t":"x","a":1e400}'),
    ('overflowing negative number', b'{"t":"x","a":-1e400}'),
    ('underflowing number is 0', b'{"t":"x","a":1e-400}'),
    ('largest integer', b'{"t":"x","a":9007199254740991}'),
    ('smallest integer', b'{"t":"x","a":-9007199254740991}'),
    ('integer beyond 2^53', b'{"t":"x","a":9007199254740992}'),
    ('integer below -2^53', b'{"t":"x","a":-9007199254740992}'),
    ('integer beyond 2^64', b'{"t":"x","a":123456789012345678901234567890}'),
    ('large float is fine', b'{"t":"x","a":9007199254740993.0}'),
    ('minus zero', b'{"t":"x","a":-0}'),
    ('minus zero float', b'{"t":"x","a":-0.0}'),
    ('leading zero', b'{"t":"x","a":01}'),
    ('leading plus', b'{"t":"x","a":+1}'),
    ('bare dot', b'{"t":"x","a":.5}'),
    ('trailing dot', b'{"t":"x","a":1.}'),
    ('bare exponent', b'{"t":"x","a":1e}'),
    ('exponent sign only', b'{"t":"x","a":1e+}'),
    ('uppercase exponent', b'{"t":"x","a":1E5}'),
    ('hex number', b'{"t":"x","a":0x10}'),
    ('true false null', b'{"t":"x","a":true,"b":false,"c":null}'),
    ('capitalised literal', b'{"t":"x","a":True}'),
    ('duplicate member', b'{"t":"x","a":1,"a":1}'),
    ('duplicate t', b'{"t":"x","t":"x"}'),
    ('duplicate in nested object', b'{"t":"x","a":{"b":1,"b":2}}'),
    ('same name after escaping', b'{"t":"x","a":1,"\\u0061":2}'),
    ('empty member name', b'{"t":"x","":1}'),
    ('escaped NUL', b'{"t":"x","a":"\\u0000"}'),
    ('raw NUL', b'{"t":"x","a":"\x00"}'),
    ('raw newline in string', b'{"t":"x","a":"\n"}'),
    ('raw tab in string', b'{"t":"x","a":"\t"}'),
    ('raw DEL in string', b'{"t":"x","a":"\x7f"}'),
    ('all simple escapes', b'{"t":"x","a":"\\"\\\\\\/\\b\\f\\n\\r\\t"}'),
    ('invalid escape', b'{"t":"x","a":"\\x"}'),
    ('short unicode escape', b'{"t":"x","a":"\\u12"}'),
    ('uppercase unicode escape', b'{"t":"x","a":"\\u00E9"}'),
    ('surrogate pair', b'{"t":"x","a":"\\ud83d\\uddfa"}'),
    ('lone high surrogate', b'{"t":"x","a":"\\ud800"}'),
    ('lone low surrogate', b'{"t":"x","a":"\\udc00"}'),
    ('high surrogate then letter', b'{"t":"x","a":"\\ud800A"}'),
    ('high surrogate then non-low escape', b'{"t":"x","a":"\\ud800\\u0041"}'),
    ('two high surrogates', b'{"t":"x","a":"\\ud800\\ud800"}'),
    ('low then high surrogate', b'{"t":"x","a":"\\udc00\\ud800"}'),
    ('lone surrogate in a member name', b'{"t":"x","\\ud800":1}'),
    ('lone surrogate as t', b'{"t":"\\ud800"}'),
    ('UTF-8 two bytes', '{"t":"x","a":"é"}'.encode()),
    ('UTF-8 four bytes', '{"t":"x","a":"🗺"}'.encode()),
    ('overlong two-byte', b'{"t":"x","a":"\xc0\xaf"}'),
    ('overlong three-byte', b'{"t":"x","a":"\xe0\x80\xaf"}'),
    ('overlong four-byte', b'{"t":"x","a":"\xf0\x80\x80\xaf"}'),
    ('encoded surrogate', b'{"t":"x","a":"\xed\xa0\x80"}'),
    ('beyond U+10FFFF', b'{"t":"x","a":"\xf4\x90\x80\x80"}'),
    ('U+10FFFF', b'{"t":"x","a":"\xf4\x8f\xbf\xbf"}'),
    ('noncharacter U+FFFE', b'{"t":"x","a":"\xef\xbf\xbe"}'),
    ('truncated sequence', b'{"t":"x","a":"\xe2\x82"}'),
    ('lone continuation byte', b'{"t":"x","a":"\x80"}'),
    ('byte 0xff', b'{"t":"x","a":"\xff"}'),
    ('UTF-8 BOM', b'\xef\xbb\xbf{"t":"x"}'),
    ('non-ASCII outside strings', b'{"t":"x"}\xc2\xa0'),
    ('deep nesting', b'{"t":"x","a":' + b'[' * 200 + b']' * 200 + b'}'),
    ('unterminated string', b'{"t":"x'),
    ('unterminated object', b'{"t":"x"'),
    ('missing colon', b'{"t" "x"}'),
    ('number as member name', b'{"t":"x",1:2}'),
]


def verdict(data: bytes) -> bool:
    try:
        P.decode_plaintext(data)
        return True
    except Exception:
        return False


SPECIALS = [b'\x00', b'\x1f', b'\x7f', b'\x80', b'\xc0', b'\xed', b'\xf4', b'\xff', b'"', b'\\', b'{', b'}', b',',
            b':', b'[', b']', b'-', b'.', b'e', b'0', b' ', b'\\u0000', b'\\ud800', b'\\udc00', b'\\ud83d\\uddfa',
            b'\\u00e9', b'1e400', b'9007199254740992', b'-0', b'1.0', b'NaN', b'true', b'null']


def mutate(base: bytes, r: random.Random) -> bytes:
    data = bytearray(base)
    for _ in range(r.randint(1, 3)):
        op = r.randrange(5)
        pos = r.randrange(len(data) + 1)
        if op == 0 and data:                       # flip a byte
            data[min(pos, len(data) - 1)] = r.randrange(256)
        elif op == 1:                              # insert a special token
            data[pos:pos] = r.choice(SPECIALS)
        elif op == 2 and data:                     # delete a few bytes
            del data[pos:pos + r.randint(1, 3)]
        elif op == 3:                              # duplicate a member
            text = data.decode('latin-1')
            i = text.find(',"', 1)
            j = text.find(',', i + 1) if i >= 0 else -1
            if i >= 0 and j > i:
                data[i:i] = text[i:j].encode('latin-1')
        else:                                      # replace a number
            text = data.decode('latin-1')
            starts = [k for k, c in enumerate(text) if c.isdigit() and (k == 0 or not text[k - 1].isalnum())]
            if starts:
                k = r.choice(starts)
                end = k
                while end < len(text) and (text[end].isdigit() or text[end] in '.eE+-'):
                    end += 1
                data[k:end] = r.choice([b'1e400', b'9007199254740992', b'-0', b'1.0', b'01', b'1e-400',
                                        b'-9007199254740991', b'2.5', b'true'])
    return bytes(data)


def main():
    cases = [{'note': note, 'hex': data.hex(), 'valid': verdict(data)} for note, data in HAND]
    r = random.Random(20261011)
    bases = [json.dumps(b, separators=(',', ':'), ensure_ascii=False).encode('utf-8') for b in BASES]
    for b in bases:
        cases.append({'note': 'base', 'hex': b.hex(), 'valid': verdict(b)})
    for i in range(480):
        data = mutate(r.choice(bases), r)
        cases.append({'note': 'mutation %d' % i, 'hex': data.hex(), 'valid': verdict(data)})
    out = {'description': 'Plaintext decoding (spec §5, §12 item 5): each input with the verdict of the Python '
                          'reference. Another implementation must reach the same verdict on every input.',
           'cases': cases}
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors',
                                                              'profile_cases.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=0, ensure_ascii=False)
        f.write('\n')
    valid = sum(c['valid'] for c in cases)
    print('wrote %s: %d cases, %d valid' % (path, len(cases), valid))


if __name__ == '__main__':
    main()
