#pragma once

#include "live_location/crypto/bytes.hpp"

#include <initializer_list>

namespace live_location::crypto
{
using Digest = ByteArray<32>;

Digest Sha256(ByteSpan data);
/// SHA-256 of the concatenation of `parts`.
Digest Sha256Concat(std::initializer_list<ByteSpan> parts);

Key HmacSha256(ByteSpan key, ByteSpan data);
/// HMAC-SHA256 of the concatenation of `parts`.
Key HmacSha256Concat(ByteSpan key, std::initializer_list<ByteSpan> parts);
}  // namespace live_location::crypto
