#pragma once

#include "live_location/nostr/event.hpp"
#include "live_location/nostr/filter.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// NIP-01 messages between a client and a relay.
namespace live_location::nostr
{
/// ["EVENT",{…}]
std::string EventMessage(Event const & event);
/// ["REQ","<id>",{…},…]
std::string ReqMessage(std::string const & subscriptionId, std::vector<Filter> const & filters);
/// ["CLOSE","<id>"]
std::string CloseMessage(std::string const & subscriptionId);

struct RelayMessage
{
  enum class Type
  {
    Event,   // ["EVENT", sub, event]
    Ok,      // ["OK", event id, accepted, message]
    Eose,    // ["EOSE", sub]
    Closed,  // ["CLOSED", sub, message]
    Notice,  // ["NOTICE", message]
  };

  Type m_type = Type::Notice;
  std::string m_subscriptionId;  // Event, Eose, Closed
  std::optional<Event> m_event;  // Event: nothing if the event is not well typed
  std::string m_eventId;         // Ok
  bool m_accepted = false;       // Ok
  std::string m_message;         // Ok, Closed, Notice
};

/// Relay messages larger than this are dropped unread: NLL events are about 1 KB.
size_t constexpr kMaxRelayMessage = 64 * 1024;

/// A message from a relay, or nothing for anything malformed, oversized or of another type (AUTH, COUNT…).
std::optional<RelayMessage> ParseRelayMessage(std::string_view text);
}  // namespace live_location::nostr
