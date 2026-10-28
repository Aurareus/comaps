#include "live_location/crypto/sha256.hpp"

#include "live_location/crypto/secp256k1_sha256.h"

namespace live_location::crypto
{
Digest Sha256(ByteSpan data)
{
  return Sha256Concat({data});
}

Digest Sha256Concat(std::initializer_list<ByteSpan> parts)
{
  nll_sha256_ctx ctx;
  nll_sha256_init(&ctx);
  for (auto const & part : parts)
    nll_sha256_update(&ctx, part.data(), part.size());
  Digest out;
  nll_sha256_final(&ctx, out.data());
  return out;
}

Key HmacSha256(ByteSpan key, ByteSpan data)
{
  return HmacSha256Concat(key, {data});
}

Key HmacSha256Concat(ByteSpan key, std::initializer_list<ByteSpan> parts)
{
  nll_hmac_sha256_ctx ctx;
  nll_hmac_sha256_init(&ctx, key.data(), key.size());
  for (auto const & part : parts)
    nll_hmac_sha256_update(&ctx, part.data(), part.size());
  Key out;
  nll_hmac_sha256_final(&ctx, out.data());
  return out;
}
}  // namespace live_location::crypto
