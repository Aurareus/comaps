"""Cryptographic primitives for the reference implementation.

Deliberately built on independent, widely used libraries so the C++ implementation
(monocypher + libsecp256k1 + vendored SHA-256) can be cross-checked against it:
  * hashlib / hmac (stdlib) for SHA-256 and HMAC-SHA256
  * PyCA cryptography (OpenSSL) for ChaCha20, ChaCha20-Poly1305 and X25519
  * coincurve (libsecp256k1) for BIP-340 Schnorr and secp256k1 point arithmetic
"""

import base64
import hashlib
import hmac

import coincurve
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    if len(prk) < 32:
        raise ValueError('prk too short')
    if length > 255 * 32:
        raise ValueError('length too large')
    out = b''
    block = b''
    counter = 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def chacha20_ietf(key: bytes, nonce12: bytes, data: bytes, counter: int = 0) -> bytes:
    """RFC 8439 ChaCha20 (32-bit counter, 96-bit nonce)."""
    if len(key) != 32 or len(nonce12) != 12:
        raise ValueError('bad chacha20 key/nonce size')
    full_nonce = counter.to_bytes(4, 'little') + nonce12
    enc = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor()
    return enc.update(data) + enc.finalize()


def chachapoly_encrypt(key: bytes, nonce12: bytes, ad: bytes, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce12, plaintext, ad)


def chachapoly_decrypt(key: bytes, nonce12: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce12, ciphertext, ad)


def x25519_public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519(secret: bytes, public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))


def secp_is_valid_secret(sk: bytes) -> bool:
    v = int.from_bytes(sk, 'big')
    return len(sk) == 32 and 0 < v < SECP256K1_N


def secp_is_valid_xonly(xonly_pub: bytes) -> bool:
    """32 bytes that are the x coordinate of a curve point (BIP-340 lift_x succeeds)."""
    if len(xonly_pub) != 32:
        return False
    try:
        coincurve.PublicKeyXOnly(xonly_pub)
        return True
    except Exception:
        return False


def secp_xonly_pub(sk: bytes) -> bytes:
    """BIP-340 x-only public key of a secret key."""
    return coincurve.PrivateKey(sk).public_key.format(compressed=True)[1:]


def schnorr_sign(sk: bytes, msg32: bytes, aux32: bytes) -> bytes:
    """BIP-340 signature. aux32 is the auxiliary randomness (fixed in test vectors)."""
    return coincurve.PrivateKey(sk).sign_schnorr(msg32, aux32)


def schnorr_verify(xonly_pub: bytes, msg32: bytes, sig: bytes) -> bool:
    try:
        return coincurve.PublicKeyXOnly(xonly_pub).verify(sig, msg32)
    except Exception:
        return False


def secp_ecdh_x(sk: bytes, xonly_pub: bytes) -> bytes:
    """Unhashed x coordinate of sk * P, where P is the even-y lift of an x-only key (NIP-44)."""
    point = coincurve.PublicKey(b'\x02' + xonly_pub).multiply(sk)
    return point.format(compressed=True)[1:]


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64decode(text: str) -> bytes:
    """Strict: only the alphabet, correct padding, and canonical (the input is what encoding gives back).
    A lax decoder accepts inputs a strict one refuses, so two implementations would disagree."""
    data = base64.b64decode(text.encode('ascii'), validate=True)
    if b64encode(data) != text:
        raise ValueError('non-canonical base64')
    return data


def b64url_nopad_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def b64url_nopad_decode(text: str) -> bytes:
    """Strict, like b64decode: alphabet, no padding, canonical."""
    if any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in text):
        raise ValueError('invalid base64url')
    data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    if b64url_nopad_encode(data) != text:
        raise ValueError('non-canonical base64url')
    return data
