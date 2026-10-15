#include "live_location/crypto/chacha.hpp"

#include <stdexcept>

#include <monocypher.h>

namespace live_location::crypto
{
namespace
{
size_t constexpr kTagSize = 16;

void CheckKeyAndNonce(ByteSpan key, ByteSpan nonce)
{
  if (key.size() != 32 || nonce.size() != 12)
    throw std::invalid_argument("ChaCha20: the key must be 32 bytes and the nonce 12");
}
}  // namespace

Bytes ChaCha20(ByteSpan key, ByteSpan nonce, ByteSpan data, uint32_t counter)
{
  Bytes out(data.size());
  ChaCha20Into(key, nonce, data, out, counter);
  return out;
}

void ChaCha20Into(ByteSpan key, ByteSpan nonce, ByteSpan data, std::span<uint8_t> out, uint32_t counter)
{
  CheckKeyAndNonce(key, nonce);
  if (out.size() != data.size())
    throw std::invalid_argument("ChaCha20: the output must be as large as the input");
  crypto_chacha20_ietf(out.data(), data.data(), data.size(), key.data(), nonce.data(), counter);
}

// Monocypher's AEAD context rekeys itself after each message, so each message gets a fresh context:
// its first message is exactly RFC 8439 ChaCha20-Poly1305.
Bytes AeadSeal(ByteSpan key, ByteSpan nonce, ByteSpan ad, ByteSpan plaintext)
{
  CheckKeyAndNonce(key, nonce);
  Bytes out(plaintext.size() + kTagSize);
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
  crypto_aead_write(&ctx, out.data(), out.data() + plaintext.size(), ad.data(), ad.size(), plaintext.data(),
                    plaintext.size());
  crypto_wipe(&ctx, sizeof(ctx));
  return out;
}

std::optional<SecretBytes> AeadOpen(ByteSpan key, ByteSpan nonce, ByteSpan ad, ByteSpan sealed)
{
  CheckKeyAndNonce(key, nonce);
  if (sealed.size() < kTagSize)
    return {};
  size_t const textSize = sealed.size() - kTagSize;
  SecretBytes out(textSize);
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
  int const result =
      crypto_aead_read(&ctx, out.data(), sealed.data() + textSize, ad.data(), ad.size(), sealed.data(), textSize);
  crypto_wipe(&ctx, sizeof(ctx));
  if (result != 0)
    return {};
  return out;
}
}  // namespace live_location::crypto
