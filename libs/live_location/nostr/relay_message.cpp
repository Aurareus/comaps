#include "live_location/nostr/relay_message.hpp"

#include "live_location/protocol/json.hpp"

#include <memory>

namespace live_location::nostr
{
namespace
{
struct JsonDeleter
{
  void operator()(json_t * json) const { json_decref(json); }
};

std::optional<std::string> StringAt(json_t const * array, size_t index)
{
  json_t const * value = json_array_get(array, index);
  if (value == nullptr || !json_is_string(value))
    return {};
  return std::string(json_string_value(value), json_string_length(value));
}
}  // namespace

std::string EventMessage(Event const & event)
{
  return "[\"EVENT\"," + ToJson(event) + "]";
}

std::string ReqMessage(std::string const & subscriptionId, std::vector<Filter> const & filters)
{
  auto out = json::Value::Array();
  out.Push(json::Value::String("REQ")).Push(json::Value::String(subscriptionId));
  std::string text = out.Dump();
  text.pop_back();  // "]": the filters are JSON already
  for (auto const & filter : filters)
    text += "," + filter.ToJson();
  return text + "]";
}

std::string CloseMessage(std::string const & subscriptionId)
{
  auto out = json::Value::Array();
  out.Push(json::Value::String("CLOSE")).Push(json::Value::String(subscriptionId));
  return out.Dump();
}

std::optional<RelayMessage> ParseRelayMessage(std::string_view text)
{
  if (text.size() > kMaxRelayMessage)
    return {};
  json_error_t error;
  std::unique_ptr<json_t, JsonDeleter> const root(json_loadb(text.data(), text.size(), JSON_REJECT_DUPLICATES, &error));
  if (!root || !json_is_array(root.get()) || json_array_size(root.get()) < 2)
    return {};
  json_t const * array = root.get();
  auto const type = StringAt(array, 0);
  if (!type)
    return {};

  RelayMessage out;
  size_t const size = json_array_size(array);
  if (*type == "EVENT" && size == 3)
  {
    auto sub = StringAt(array, 1);
    if (!sub)
      return {};
    out.m_type = RelayMessage::Type::Event;
    out.m_subscriptionId = std::move(*sub);
    out.m_event = FromJson(json_array_get(array, 2));
  }
  else if (*type == "OK" && size >= 3)
  {
    auto id = StringAt(array, 1);
    json_t const * accepted = json_array_get(array, 2);
    if (!id || !json_is_boolean(accepted))
      return {};
    out.m_type = RelayMessage::Type::Ok;
    out.m_eventId = std::move(*id);
    out.m_accepted = json_is_true(accepted);
    out.m_message = StringAt(array, 3).value_or("");
  }
  else if (*type == "EOSE")
  {
    auto sub = StringAt(array, 1);
    if (!sub)
      return {};
    out.m_type = RelayMessage::Type::Eose;
    out.m_subscriptionId = std::move(*sub);
  }
  else if (*type == "CLOSED")
  {
    auto sub = StringAt(array, 1);
    if (!sub)
      return {};
    out.m_type = RelayMessage::Type::Closed;
    out.m_subscriptionId = std::move(*sub);
    out.m_message = StringAt(array, 2).value_or("");
  }
  else if (*type == "NOTICE")
  {
    out.m_type = RelayMessage::Type::Notice;
    out.m_message = StringAt(array, 1).value_or("");
  }
  else
  {
    return {};
  }
  return out;
}
}  // namespace live_location::nostr
