#pragma once

#include "live_location/crypto/bytes.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <jansson.h>

// NIP-01 events: canonical serialisation, id, BIP-340 signature.
namespace live_location::nostr
{
using Tag = std::vector<std::string>;
using Tags = std::vector<Tag>;

struct Event
{
  std::string m_id;      // 64 lowercase hex
  std::string m_pubkey;  // 64 lowercase hex, x-only
  int64_t m_createdAt = 0;
  int64_t m_kind = 0;
  Tags m_tags;
  std::string m_content;
  std::string m_sig;  // 128 lowercase hex

  /// The second element of the first tag with this name (spec §12 item 2); nothing if there is none.
  std::optional<std::string> TagValue(std::string_view name) const;
};

/// [0,pubkey,created_at,kind,tags,content] with the escaping of NIP-01: only the seven characters it
/// lists are escaped, everything else is written verbatim.
std::string Serialize(Event const & event);
std::string ComputeId(Event const & event);

/// Sets the pubkey, id and signature. `auxRandom` is BIP-340's auxiliary randomness.
void Sign(Event & event, Key const & secretKey, ByteArray<32> const & auxRandom);
/// The id is the hash of the serialisation and the signature is valid for the pubkey.
bool Verify(Event const & event);

/// The event object as relays carry it.
std::string ToJson(Event const & event);
/// The event object of a relay message. Nothing unless every field has its NIP-01 type: id, pubkey and
/// sig lowercase hex of the right length, integer created_at and kind, tags an array of arrays of
/// strings, content a string. Extra members are ignored.
std::optional<Event> FromJson(json_t const * object);
}  // namespace live_location::nostr
