#pragma once

#include "live_location/encoding/binary.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/invite.hpp"
#include "live_location/protocol/messages.hpp"

#include <optional>

// The store's encoding of protocol objects (design doc §8.5). Readers throw binary::FormatError.
namespace live_location::persist
{
/// The largest time written anywhere: ten digits of seconds, until the year 2286 (spec §12 item 3), and its epoch.
int64_t constexpr kMaxTime = 9'999'999'999;
int64_t constexpr kMaxEpoch = kMaxTime / kEpochSeconds;

/// An integer the store holds, refused when outside [lo, hi]. Its authenticated encryption keeps damage out, so
/// such a value could only come from a bug; read anyway, a negative epoch would ratchet a chain ~10^12 times, and
/// a time near the integer's limit would overflow.
int64_t ReadI64(binary::Reader & reader, int64_t lo, int64_t hi, char const * what);

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
