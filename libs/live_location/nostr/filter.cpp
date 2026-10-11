#include "live_location/nostr/filter.hpp"

#include "live_location/protocol/json.hpp"

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
}  // namespace live_location::nostr
