"""NIP-44 version 2 (https://github.com/nostr-protocol/nips/blob/master/44.md).

The live-location protocol uses NIP-44 v2 unchanged from step 2 onwards; only the
conversation key is derived differently (from protocol secrets instead of ECDH).
"""

import hmac as _hmac
import math
import os

from . import primitives as p

VERSION = 2
MIN_PLAINTEXT = 1
MAX_PLAINTEXT = 0xFFFFFFFF


def get_conversation_key(sk: bytes, xonly_pub: bytes) -> bytes:
    return p.hkdf_extract(b'nip44-v2', p.secp_ecdh_x(sk, xonly_pub))


def get_message_keys(conversation_key: bytes, nonce: bytes):
    if len(conversation_key) != 32:
        raise ValueError('invalid conversation_key length')
    if len(nonce) != 32:
        raise ValueError('invalid nonce length')
    keys = p.hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]


def calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len <= 0:
        raise ValueError('expected positive integer')
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((unpadded_len - 1) / chunk) + 1)


def pad(plaintext: bytes) -> bytes:
    n = len(plaintext)
    if n < MIN_PLAINTEXT or n > MAX_PLAINTEXT:
        raise ValueError('invalid plaintext length')
    if n < 65536:
        prefix = n.to_bytes(2, 'big')
    else:
        prefix = b'\x00\x00' + n.to_bytes(4, 'big')
    return prefix + plaintext + bytes(calc_padded_len(n) - n)


# The live-location profile never needs the extended (6-byte) length prefix: all of its
# plaintexts are far below 64 KiB. Capping keeps it compatible with implementations of the
# original NIP-44 v2 text and shrinks the parser surface.
PROFILE_MAX_PLAINTEXT = 65535


def pad_profile(plaintext: bytes) -> bytes:
    if len(plaintext) > PROFILE_MAX_PLAINTEXT:
        raise ValueError('plaintext too long for profile')
    return pad(plaintext)


def unpad(padded: bytes) -> bytes:
    if len(padded) < 2:
        raise ValueError('invalid padding')
    n = int.from_bytes(padded[0:2], 'big')
    offset = 2
    if n == 0:
        if len(padded) < 6:
            raise ValueError('invalid padding')
        n = int.from_bytes(padded[2:6], 'big')
        offset = 6
        if n < 65536:
            raise ValueError('invalid padding')
    plaintext = padded[offset:offset + n]
    if n == 0 or len(plaintext) != n or len(padded) != offset + calc_padded_len(n):
        raise ValueError('invalid padding')
    return plaintext


def hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise ValueError('AAD associated data must be 32 bytes')
    return p.hmac_sha256(key, aad + message)


def encrypt(plaintext: str | bytes, conversation_key: bytes, nonce: bytes | None = None) -> str:
    if nonce is None:
        nonce = os.urandom(32)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    ciphertext = p.chacha20_ietf(chacha_key, chacha_nonce, pad(plaintext))
    mac = hmac_aad(hmac_key, ciphertext, nonce)
    return p.b64encode(bytes([VERSION]) + nonce + ciphertext + mac)


def decode_payload(payload: str):
    plen = len(payload)
    if plen == 0 or payload[0] == '#':
        raise ValueError('unknown version')
    if plen < 132:
        raise ValueError('invalid payload size')
    data = p.b64decode(payload)
    dlen = len(data)
    if dlen < 99:
        raise ValueError('invalid data size')
    if data[0] != VERSION:
        raise ValueError('unknown version ' + str(data[0]))
    return data[1:33], data[33:dlen - 32], data[dlen - 32:dlen]


def decrypt_bytes(payload: str, conversation_key: bytes) -> bytes:
    nonce, ciphertext, mac = decode_payload(payload)
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    calculated = hmac_aad(hmac_key, ciphertext, nonce)
    if not _hmac.compare_digest(calculated, mac):
        raise ValueError('invalid MAC')
    return unpad(p.chacha20_ietf(chacha_key, chacha_nonce, ciphertext))


def decrypt(payload: str, conversation_key: bytes) -> str:
    return decrypt_bytes(payload, conversation_key).decode('utf-8')
