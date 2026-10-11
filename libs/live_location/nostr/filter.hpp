#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace live_location::nostr
{
/// A NIP-01 subscription filter, with the fields NLL uses.
struct Filter
{
  std::vector<int64_t> m_kinds;
  std::vector<std::string> m_authors;
  std::vector<std::string> m_pTags;  // "#p"
  std::optional<int64_t> m_since;

  /// {"kinds":[…],"authors":[…],"#p":[…],"since":…}, with empty lists and an absent since left out.
  std::string ToJson() const;

  bool operator==(Filter const &) const = default;
};
}  // namespace live_location::nostr
