"""Noise Protocol Framework (revision 34) subset: 25519, ChaChaPoly, SHA256.

Only what the live-location pairing needs (NNpsk0), written generically enough to be
checked against the published cacophony test vectors.
"""

import os

from . import primitives as p

HASHLEN = 32
DHLEN = 32

PATTERNS = {
    # name: (pre-messages, messages)
    'NN': ([], [['e'], ['e', 'ee']]),
    'NNpsk0': ([], [['psk', 'e'], ['e', 'ee']]),
}


def hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int):
    temp_key = p.hmac_sha256(chaining_key, ikm)
    out1 = p.hmac_sha256(temp_key, b'\x01')
    out2 = p.hmac_sha256(temp_key, out1 + b'\x02')
    if num_outputs == 2:
        return out1, out2
    out3 = p.hmac_sha256(temp_key, out2 + b'\x03')
    return out1, out2, out3


class CipherState:
    def __init__(self, key: bytes | None = None):
        self.k = key
        self.n = 0

    def has_key(self) -> bool:
        return self.k is not None

    def _nonce(self) -> bytes:
        return b'\x00\x00\x00\x00' + self.n.to_bytes(8, 'little')

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        out = p.chachapoly_encrypt(self.k, self._nonce(), ad, plaintext)
        self.n += 1
        return out

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        out = p.chachapoly_decrypt(self.k, self._nonce(), ad, ciphertext)
        self.n += 1
        return out


class SymmetricState:
    def __init__(self, protocol_name: bytes):
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + bytes(HASHLEN - len(protocol_name))
        else:
            self.h = p.sha256(protocol_name)
        self.ck = self.h
        self.cipher = CipherState()

    def mix_key(self, ikm: bytes):
        self.ck, temp_k = hkdf(self.ck, ikm, 2)
        self.cipher = CipherState(temp_k)

    def mix_hash(self, data: bytes):
        self.h = p.sha256(self.h + data)

    def mix_key_and_hash(self, ikm: bytes):
        self.ck, temp_h, temp_k = hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cipher = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        temp_k1, temp_k2 = hkdf(self.ck, b'', 2)
        return CipherState(temp_k1), CipherState(temp_k2), temp_k1, temp_k2


class HandshakeState:
    """Supports the 'NN' and 'NNpsk0' patterns over 25519/ChaChaPoly/SHA256."""

    def __init__(self, pattern: str, initiator: bool, prologue: bytes = b'', psk: bytes | None = None,
                 e_secret: bytes | None = None):
        _, self.messages = PATTERNS[pattern]
        self.psk_mode = 'psk' in pattern
        if self.psk_mode and (psk is None or len(psk) != 32):
            raise ValueError('psk required')
        self.ss = SymmetricState(('Noise_' + pattern + '_25519_ChaChaPoly_SHA256').encode('ascii'))
        self.ss.mix_hash(prologue)
        self.initiator = initiator
        self.psk = psk
        self.e_secret = e_secret
        self.e_public = None
        self.re = None
        self.msg_index = 0

    def _dh_ee(self) -> bytes:
        # A low-order public key makes X25519 return all zeros. PyCA refuses it, Monocypher returns the
        # zeros; NLL makes both abort (spec §3), as RFC 7748 §6.1 allows.
        try:
            shared = p.x25519(self.e_secret, self.re)
        except ValueError:
            shared = bytes(32)
        if shared == bytes(32):
            raise ValueError('all-zero DH result: low-order public key')
        return shared

    def write_message(self, payload: bytes) -> bytes:
        tokens = self.messages[self.msg_index]
        self.msg_index += 1
        out = b''
        for token in tokens:
            if token == 'e':
                if self.e_secret is None:
                    self.e_secret = os.urandom(32)
                self.e_public = p.x25519_public(self.e_secret)
                out += self.e_public
                self.ss.mix_hash(self.e_public)
                if self.psk_mode:
                    self.ss.mix_key(self.e_public)
            elif token == 'ee':
                self.ss.mix_key(self._dh_ee())
            elif token == 'psk':
                self.ss.mix_key_and_hash(self.psk)
            else:
                raise ValueError('unsupported token ' + token)
        return out + self.ss.encrypt_and_hash(payload)

    def read_message(self, message: bytes) -> bytes:
        tokens = self.messages[self.msg_index]
        self.msg_index += 1
        for token in tokens:
            if token == 'e':
                if len(message) < DHLEN:
                    raise ValueError('message too short')
                self.re, message = message[:DHLEN], message[DHLEN:]
                self.ss.mix_hash(self.re)
                if self.psk_mode:
                    self.ss.mix_key(self.re)
            elif token == 'ee':
                self.ss.mix_key(self._dh_ee())
            elif token == 'psk':
                self.ss.mix_key_and_hash(self.psk)
            else:
                raise ValueError('unsupported token ' + token)
        return self.ss.decrypt_and_hash(message)

    def is_complete(self) -> bool:
        return self.msg_index == len(self.messages)

    def handshake_hash(self) -> bytes:
        return self.ss.h
