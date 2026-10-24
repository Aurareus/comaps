#pragma once

#include "live_location/crypto/bytes.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace live_location
{
/// RFC 4648 base64 with padding.
std::string Base64Encode(ByteSpan data);

/// Strict (spec §2): only the alphabet, padding to a multiple of 4, and canonical, so that encoding
/// the result gives the input back. A lax decoder would accept inputs that a strict one refuses, and two
/// implementations would disagree on what a message is.
std::optional<Bytes> Base64Decode(std::string_view text);

/// RFC 4648 base64url without padding (invites).
std::string Base64UrlEncode(ByteSpan data);

/// Strict, like Base64Decode: only the URL-safe alphabet, no padding, canonical.
std::optional<Bytes> Base64UrlDecode(std::string_view text);
}  // namespace live_location
