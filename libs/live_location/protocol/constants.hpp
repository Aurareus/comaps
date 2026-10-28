#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

// The constants of NLL v1 (docs/LIVE_LOCATION_PROTOCOL.md §14).
namespace live_location
{
int constexpr kKindStored = 30484;        // addressable: pairing steps, channel states, location streams
int constexpr kKindSignal = 20484;        // ephemeral: viewer -> sharer signals
int64_t constexpr kEpochSeconds = 86400;  // epochs are UTC days
size_t constexpr kSizeControl = 512;      // pairing and control plaintexts are space-padded to this size
size_t constexpr kSizeStream = 256;       // location, stream-end and signal plaintexts
size_t constexpr kMaxRelays = 4;
size_t constexpr kMaxRelayUrl = 64;                      // bytes
size_t constexpr kMaxName = 64;                          // bytes
size_t constexpr kMaxDest = 48;                          // bytes, nav.dest
int64_t constexpr kMaxJsonInt = (int64_t{1} << 53) - 1;  // I-JSON integers
uint8_t constexpr kInviteVersion = 1;
std::string_view constexpr kInviteLinkPrefix = "comaps://live/pair#";

int64_t constexpr kTtlLocation = 900;    // locations and stream ends expire 15 min after creation
int64_t constexpr kControlGrace = 3600;  // control events expire, and channel keys go, 1 h after their epoch
int64_t constexpr kMaxFutureSkew = 300;  // receivers reject events created more than 5 min ahead
int64_t constexpr kSignalMaxAge = 60;    // receivers ignore older signals
int64_t constexpr kRekeyDelayMin = 30;   // a replacement stream publishes nothing for a random 30..120 s
int64_t constexpr kRekeyDelayMax = 120;
int64_t constexpr kOkWait = 10;     // wait for an OK on each state before the old stream's end
int64_t constexpr kEndGrace = 120;  // a viewer keeps an ended stream's last position this long
size_t constexpr kDecoyBlock = 8;   // inbox subscriptions are padded to a multiple of this
size_t constexpr kMaxAuthors = 50;  // authors per REQ filter
int64_t constexpr kMaxInviteLifetime = 86400;
int64_t constexpr kConfirmEpochs = 7;  // the joiner confirms daily through epoch e_p + 7

std::array<std::string_view, 3> constexpr kDefaultRelays = {"wss://nos.lol", "wss://nostr.mom",
                                                            "wss://relay.nostr.net"};  // design D5
}  // namespace live_location
