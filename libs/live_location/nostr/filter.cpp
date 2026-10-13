#include "live_location/nostr/filter.hpp"

#include "live_location/protocol/json.hpp"

#include <algorithm>

namespace live_location::nostr
{
std::string Filter::ToJson() const
{
  auto const strings = [](std::vector<std::string> const & values)
  {
    auto out = json::Value::Array();
    for (auto const & v : values)
      out.Push(json::Value::String(v));
    return out;
  };
  auto out = json::Value::Object();
  if (!m_kinds.empty())
  {
    auto kinds = json::Value::Array();
    for (auto const kind : m_kinds)
      kinds.Push(json::Value::Int(kind));
    out.Set("kinds", std::move(kinds));
  }
  if (!m_authors.empty())
    out.Set("authors", strings(m_authors));
  if (!m_pTags.empty())
    out.Set("#p", strings(m_pTags));
  if (m_since)
    out.Set("since", json::Value::Int(*m_since));
  return out.Dump();
}

bool Matches(Filter const & filter, Event const & event)
{
  auto const has = [](auto const & values, auto const & value)
  { return values.empty() || std::find(values.begin(), values.end(), value) != values.end(); };
  if (!has(filter.m_kinds, event.m_kind) || !has(filter.m_authors, event.m_pubkey))
    return false;
  if (filter.m_since && event.m_createdAt < *filter.m_since)
    return false;
  if (filter.m_pTags.empty())
    return true;
  return std::any_of(event.m_tags.begin(), event.m_tags.end(),
                     [&](Tag const & tag) { return tag.size() >= 2 && tag[0] == "p" && has(filter.m_pTags, tag[1]); });
}

bool MatchesAny(std::vector<Filter> const & filters, Event const & event)
{
  return std::any_of(filters.begin(), filters.end(), [&](Filter const & filter) { return Matches(filter, event); });
}
}  // namespace live_location::nostr
