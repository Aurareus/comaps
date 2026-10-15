#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/protocol/messages.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace live_location
{
/// A pairing invite (spec §6.1): u8(1) || psk || ipk || u32be(expires_at) || u8(n) || (u8(len) || url)*n.
struct Invite
{
  std::optional<Key> m_psk;  // erased when the pairing ends
  ByteArray<32> m_ipk{};     // the inviter's one-time pairing key (x-only); its secret never leaves the inviter
  int64_t m_expiresAt = 0;
  Relays m_relays;

  /// Throws std::logic_error once the PSK has been erased.
  SecretBytes Encode() const;
  /// ipk || u32be(expires_at) || u8(n) || relays: the invite without its secret.
  Bytes PublicFields() const;
  /// "comaps://live/pair#" || base64url(invite).
  std::string Link() const;

  /// Strict: version 1, exact length, a valid ipk and relays valid per spec §5. Nothing otherwise.
  static std::optional<Invite> Decode(ByteSpan data);
  static std::optional<Invite> FromLink(std::string_view link);

  /// HKDF-Expand(HKDF-Extract(label("pair"), psk), label("pair-mac"), 32).
  Key MacKey() const;
  /// label("pair") || u8(1) || public fields || jpk || c: binds the handshake to the invite and to the
  /// one step 0 being answered (spec §6.3).
  Bytes Prologue(ByteSpan jpk, ByteSpan c) const;
};
}  // namespace live_location
