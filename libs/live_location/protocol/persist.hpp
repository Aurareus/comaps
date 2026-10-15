#pragma once

#include "live_location/encoding/binary.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/invite.hpp"
#include "live_location/protocol/messages.hpp"

#include <optional>

// The store's encoding of protocol objects (design doc §8.5). Readers throw binary::FormatError.
namespace live_location::persist
{
void WriteRelays(binary::Writer & writer, Relays const & relays);
/// Refuses a list that is not valid per spec §5.
Relays ReadRelays(binary::Reader & reader);

void WriteDirection(binary::Writer & writer, Direction const & direction);
Direction ReadDirection(binary::Reader & reader);

void WriteContact(binary::Writer & writer, Contact const & contact);
ContactPtr ReadContact(binary::Reader & reader);

void WriteInvite(binary::Writer & writer, Invite const & invite);
Invite ReadInvite(binary::Reader & reader);

void WriteEvent(binary::Writer & writer, nostr::Event const & event);
nostr::Event ReadEvent(binary::Reader & reader);
void WriteOptionalEvent(binary::Writer & writer, std::optional<nostr::Event> const & event);
std::optional<nostr::Event> ReadOptionalEvent(binary::Reader & reader);
}  // namespace live_location::persist
