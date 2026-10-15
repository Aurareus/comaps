#include "live_location/crypto/x25519.hpp"

#include <stdexcept>

#include <monocypher.h>

namespace live_location::crypto
{
ByteArray<32> X25519PublicKey(Key const & secret)
{
  ByteArray<32> out;
  crypto_x25519_public_key(out.data(), secret.data());
  return out;
}

std::optional<Key> X25519(Key const & secret, ByteSpan publicKey)
{
  if (publicKey.size() != 32)
    throw std::invalid_argument("X25519: the public key must be 32 bytes");
  Key shared;
  crypto_x25519(shared.data(), secret.data(), publicKey.data());
  if (ConstantTimeEqual(shared, ByteArray<32>{}))
    return {};
  return shared;
}
}  // namespace live_location::crypto
