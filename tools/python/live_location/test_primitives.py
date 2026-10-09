"""Checks the reference primitives against published vectors (NIP-44, BIP-340, Noise, RFC 5869).

Usage: test_primitives.py [CACHE_DIR]
  CACHE_DIR  where the NIP-44 vector file is downloaded to (default: vectors/cache), see
             vectors/external/SOURCES.md for why it is not vendored.
"""

import csv
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from nll import nip44, noise, primitives as p  # noqa: E402

EXTERNAL = os.path.join(HERE, 'vectors', 'external')
NIP44_URL = 'https://raw.githubusercontent.com/paulmillr/nip44/main/nip44.vectors.json'
NIP44_SHA256 = '269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040'  # published in NIP-44
failures = 0
checks = 0


def nip44_vectors(cache_dir):
    path = os.path.join(cache_dir, 'nip44.vectors.json')
    if not os.path.exists(path):
        os.makedirs(cache_dir, exist_ok=True)
        with urllib.request.urlopen(NIP44_URL, timeout=30) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != NIP44_SHA256:
            sys.exit('nip44.vectors.json checksum mismatch, refusing to use it')
        with open(path, 'wb') as f:
            f.write(data)
    with open(path, 'rb') as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != NIP44_SHA256:
        sys.exit('cached nip44.vectors.json checksum mismatch')
    return json.loads(data)['v2']


def check(cond, what):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        print('FAIL:', what)


# --- RFC 5869 test case 1 (SHA-256) ---
ikm = bytes.fromhex('0b' * 22)
salt = bytes.fromhex('000102030405060708090a0b0c')
info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
prk = p.hkdf_extract(salt, ikm)
check(prk.hex() == '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'RFC5869 TC1 PRK')
okm = p.hkdf_expand(prk, info, 42)
check(okm.hex() == '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      'RFC5869 TC1 OKM')

# --- NIP-44 v2 ---
v = nip44_vectors(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'vectors', 'cache'))
for t in v['valid']['get_conversation_key']:
    ck = nip44.get_conversation_key(bytes.fromhex(t['sec1']), bytes.fromhex(t['pub2']))
    check(ck.hex() == t['conversation_key'], 'nip44 conversation key ' + t['sec1'][:8])
mk = v['valid']['get_message_keys']
for t in mk['keys']:
    a, b, c = nip44.get_message_keys(bytes.fromhex(mk['conversation_key']), bytes.fromhex(t['nonce']))
    check(a.hex() == t['chacha_key'] and b.hex() == t['chacha_nonce'] and c.hex() == t['hmac_key'],
          'nip44 message keys ' + t['nonce'][:8])
for t in v['valid']['calc_padded_len']:
    check(nip44.calc_padded_len(t[0]) == t[1], 'nip44 padded len %d' % t[0])
for t in v['valid']['encrypt_decrypt']:
    ck = nip44.get_conversation_key(bytes.fromhex(t['sec1']), p.secp_xonly_pub(bytes.fromhex(t['sec2'])))
    check(ck.hex() == t['conversation_key'], 'nip44 e/d conversation key')
    payload = nip44.encrypt(t['plaintext'], ck, bytes.fromhex(t['nonce']))
    check(payload == t['payload'], 'nip44 encrypt ' + t['plaintext'][:16])
    check(nip44.decrypt(t['payload'], ck) == t['plaintext'], 'nip44 decrypt ' + t['plaintext'][:16])
for t in v['valid']['encrypt_decrypt_long_msg']:
    plaintext = t['pattern'] * t['repeat']
    check(p.sha256(plaintext.encode()).hex() == t['plaintext_sha256'], 'nip44 long plaintext hash')
    payload = nip44.encrypt(plaintext, bytes.fromhex(t['conversation_key']), bytes.fromhex(t['nonce']))
    check(p.sha256(payload.encode()).hex() == t['payload_sha256'], 'nip44 long payload hash')
# The checksum-pinned vector file predates the extended-length amendment of NIP-44: it lists
# 65536+ as invalid. Our protocol profile caps plaintexts at 65535 bytes, so those must be
# rejected by the profile check, while plain NIP-44 must follow the amended text.
for t in v['invalid']['encrypt_msg_lengths']:
    try:
        nip44.pad_profile(b'a' * t)
        check(False, 'nip44 profile accepted invalid length %d' % t)
    except ValueError:
        check(True, '')
EXT_CK = bytes.fromhex('c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d')
EXT_NONCE = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
for n, pt_hash, payload_hash in [
    (65535, '6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42',
     '6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84'),
    (65536, 'bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a',
     'b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616'),
    (65537, '008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430',
     'eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435')]:
    pt = b'a' * n
    check(p.sha256(pt).hex() == pt_hash, 'nip44 extended plaintext %d' % n)
    payload = nip44.encrypt(pt, EXT_CK, EXT_NONCE)
    check(p.sha256(payload.encode()).hex() == payload_hash, 'nip44 extended payload %d' % n)
    check(nip44.decrypt_bytes(payload, EXT_CK) == pt, 'nip44 extended roundtrip %d' % n)
for t in v['invalid']['get_conversation_key']:
    try:
        nip44.get_conversation_key(bytes.fromhex(t['sec1']), bytes.fromhex(t['pub2']))
        check(False, 'nip44 invalid conversation key accepted: ' + t['note'])
    except Exception:
        check(True, '')
for t in v['invalid']['decrypt']:
    try:
        nip44.decrypt(t['payload'], bytes.fromhex(t['conversation_key']))
        check(False, 'nip44 invalid decrypt accepted: ' + t['note'])
    except Exception:
        check(True, '')

# --- BIP-340 ---
with open(os.path.join(EXTERNAL, 'bip340-test-vectors.csv')) as f:
    for row in csv.DictReader(f):
        msg = bytes.fromhex(row['message'])
        if len(msg) != 32:
            continue  # coincurve only signs 32-byte messages; Nostr ids are always 32 bytes
        pub = bytes.fromhex(row['public key'])
        sig = bytes.fromhex(row['signature'])
        expected = row['verification result'] == 'TRUE'
        if row['secret key']:
            sk = bytes.fromhex(row['secret key'])
            check(p.secp_xonly_pub(sk) == pub, 'bip340 pubkey #' + row['index'])
            check(p.schnorr_sign(sk, msg, bytes.fromhex(row['aux_rand'])) == sig, 'bip340 sign #' + row['index'])
        check(p.schnorr_verify(pub, msg, sig) == expected, 'bip340 verify #' + row['index'])

# --- Noise NNpsk0 (cacophony) ---
cac = [json.load(open(os.path.join(EXTERNAL, 'noise_NNpsk0_25519_ChaChaPoly_SHA256.json')))]
found = 0
for t in cac:
    if t.get('protocol_name') != 'Noise_NNpsk0_25519_ChaChaPoly_SHA256':
        continue
    found += 1
    init = noise.HandshakeState('NNpsk0', True, bytes.fromhex(t['init_prologue']), bytes.fromhex(t['init_psks'][0]),
                                bytes.fromhex(t['init_ephemeral']))
    resp = noise.HandshakeState('NNpsk0', False, bytes.fromhex(t['resp_prologue']), bytes.fromhex(t['resp_psks'][0]),
                                bytes.fromhex(t['resp_ephemeral']))
    msgs = t['messages']
    m0 = init.write_message(bytes.fromhex(msgs[0]['payload']))
    check(m0.hex() == msgs[0]['ciphertext'], 'noise msg0')
    check(resp.read_message(m0).hex() == msgs[0]['payload'], 'noise msg0 read')
    m1 = resp.write_message(bytes.fromhex(msgs[1]['payload']))
    check(m1.hex() == msgs[1]['ciphertext'], 'noise msg1')
    check(init.read_message(m1).hex() == msgs[1]['payload'], 'noise msg1 read')
    check(init.handshake_hash().hex() == t['handshake_hash'], 'noise handshake hash (init)')
    check(resp.handshake_hash().hex() == t['handshake_hash'], 'noise handshake hash (resp)')
    ic1, ic2, _, _ = init.ss.split()
    rc1, rc2, _, _ = resp.ss.split()
    for i, m in enumerate(msgs[2:]):
        if i % 2 == 0:
            ct = ic1.encrypt_with_ad(b'', bytes.fromhex(m['payload']))
            check(rc1.decrypt_with_ad(b'', ct).hex() == m['payload'], 'noise transport read %d' % i)
        else:
            ct = rc2.encrypt_with_ad(b'', bytes.fromhex(m['payload']))
            check(ic2.decrypt_with_ad(b'', ct).hex() == m['payload'], 'noise transport read %d' % i)
        check(ct.hex() == m['ciphertext'], 'noise transport %d' % i)
check(found == 1, 'noise vector found')

print('%d checks, %d failures' % (checks, failures))
sys.exit(1 if failures else 0)
