#pragma once

#include "live_location/crypto/bytes.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace live_location::nip44
{
/// NIP-44 version 2 as NLL profiles it (spec §3): plaintexts of 1 to 65535 bytes, so the extended
/// length prefix never occurs. Conversation keys come from the protocol's key schedule, not from ECDH.
size_t constexpr kMaxPlaintextSize = 65535;

struct MessageKeys
{
  Key m_chachaKey;
  Secret<12> m_chachaNonce;
  Key m_hmacKey;
};

MessageKeys GetMessageKeys(Key const & conversationKey, ByteArray<32> const & nonce);

/// Throws std::invalid_argument for 0.
size_t CalcPaddedLen(size_t unpaddedSize);

/// The base64 payload. Throws std::invalid_argument for a plaintext outside 1..kMaxPlaintextSize.
std::string Encrypt(ByteSpan plaintext, Key const & conversationKey, ByteArray<32> const & nonce);

/// The plaintext, or nothing if the payload is malformed, not version 2, fails its MAC, or is not
/// padded exactly as Encrypt pads.
std::optional<SecretBytes> Decrypt(std::string_view payload, Key const & conversationKey);
}  // namespace live_location::nip44
