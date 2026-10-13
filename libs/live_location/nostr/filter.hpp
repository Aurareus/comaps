#pragma once

#include "live_location/nostr/event.hpp"

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

/// NIP-01 matching: every field set in the filter holds for the event; "#p" holds when any p tag
/// carries one of its values.
bool Matches(Filter const & filter, Event const & event);
bool MatchesAny(std::vector<Filter> const & filters, Event const & event);
}  // namespace live_location::nostr
