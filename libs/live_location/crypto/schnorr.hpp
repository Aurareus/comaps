#pragma once

#include "live_location/crypto/bytes.hpp"

namespace live_location::crypto
{
using XOnlyPublicKey = ByteArray<32>;
using Signature = ByteArray<64>;

/// 32 bytes encoding an integer in [1, n - 1], n being the order of secp256k1.
bool IsValidSecretKey(ByteSpan key);

/// 32 bytes that are the x coordinate of a curve point (BIP-340 lift_x succeeds).
bool IsValidXOnlyPublicKey(ByteSpan key);

/// The BIP-340 public key. Throws std::invalid_argument for an invalid secret key.
XOnlyPublicKey GetXOnlyPublicKey(Key const & secretKey);

/// BIP-340 signature of a 32-byte message with the given auxiliary randomness. Throws
/// std::invalid_argument for an invalid secret key.
Signature SchnorrSign(Key const & secretKey, ByteArray<32> const & message, ByteArray<32> const & auxRandom);

/// BIP-340 verification, for messages of any length. False for malformed keys or signatures.
bool SchnorrVerify(ByteSpan publicKey, ByteSpan message, ByteSpan signature);
}  // namespace live_location::crypto
