#pragma once

#include "live_location/crypto/bytes.hpp"

#include <optional>

namespace live_location::crypto
{
ByteArray<32> X25519PublicKey(Key const & secret);

/// RFC 7748 X25519. Nothing when the result is all zeros, which a low-order public key causes: NLL
/// aborts then, as RFC 7748 §6.1 allows (spec §3). Throws std::invalid_argument when `publicKey` is not
/// 32 bytes.
std::optional<Key> X25519(Key const & secret, ByteSpan publicKey);
}  // namespace live_location::crypto
