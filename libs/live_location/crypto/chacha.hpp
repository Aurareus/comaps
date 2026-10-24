#pragma once

#include "live_location/crypto/bytes.hpp"

#include <optional>

namespace live_location::crypto
{
/// RFC 8439 ChaCha20: a 32-byte key, a 12-byte nonce and a 32-bit block counter. Throws
/// std::invalid_argument for other key or nonce sizes.
Bytes ChaCha20(ByteSpan key, ByteSpan nonce, ByteSpan data, uint32_t counter = 0);

/// The same into `out`, which must be as large as `data`: lets a caller decrypt straight into memory
/// that it wipes.
void ChaCha20Into(ByteSpan key, ByteSpan nonce, ByteSpan data, std::span<uint8_t> out, uint32_t counter = 0);

/// RFC 8439 ChaCha20-Poly1305: the ciphertext followed by the 16-byte tag.
Bytes AeadSeal(ByteSpan key, ByteSpan nonce, ByteSpan ad, ByteSpan plaintext);

/// The plaintext, or nothing when the input is shorter than a tag or the tag does not verify.
std::optional<SecretBytes> AeadOpen(ByteSpan key, ByteSpan nonce, ByteSpan ad, ByteSpan sealed);
}  // namespace live_location::crypto
