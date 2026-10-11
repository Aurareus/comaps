#pragma once

#include "live_location/crypto/bytes.hpp"

namespace live_location::crypto
{
/// RFC 5869 HKDF-Extract with SHA-256.
Key HkdfExtract(ByteSpan salt, ByteSpan ikm);

/// RFC 5869 HKDF-Expand with SHA-256. Throws std::invalid_argument when `prk` is shorter than 32
/// bytes or `length` exceeds 255 * 32.
SecretBytes HkdfExpand(ByteSpan prk, ByteSpan info, size_t length);

template <size_t N>
Secret<N> HkdfExpandTo(ByteSpan prk, ByteSpan info)
{
  auto const okm = HkdfExpand(prk, info, N);
  Secret<N> out;
  std::copy(okm.begin(), okm.end(), out.begin());
  return out;
}
}  // namespace live_location::crypto
