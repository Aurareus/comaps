#pragma once

#include "live_location/crypto/random.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/pairing.hpp"
#include "live_location/protocol/stream.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// The scenario harness of the C++ port of tools/python/live_location/test_protocol.py: a model relay,
// apps going online, and complete pairings.
namespace live_location_tests
{
int64_t constexpr kT0 = 1'760'000'000;  // a fixed "now" (2025-10-09T08:53:20Z)
extern live_location::Relays const kRelaysA;
extern live_location::Relays const kRelaysB;

/// One deterministic generator for all scenarios, like `rng` in the Python suite.
live_location::crypto::Rng & ScenarioRng();

/// A round trip through the JSON of a relay message, as relays would.
live_location::nostr::Event Wire(live_location::nostr::Event const & event);

/// What pairing sees of a relay: addressable events, the newest kept per (pubkey, kind, d) (NIP-01).
class ModelRelay
{
public:
  void Publish(live_location::nostr::Event const & event);
  /// Sorted by (created_at, id). With `now`, expired events are no longer served (NIP-40).
  std::vector<live_location::nostr::Event> Query(std::set<std::string> const * authors = nullptr,
                                                 std::optional<std::string> const & pTag = {},
                                                 std::optional<int64_t> now = {}) const;

private:
  std::map<std::tuple<std::string, int64_t, std::string>, live_location::nostr::Event> m_slots;
};

/// The app is open: it reads its pairing subscriptions and publishes what it is asked to. Returns the
/// outcomes; PairingAborted propagates; out-of-order events are held.
std::vector<live_location::Outcome> Online(live_location::Inviter & inviter, ModelRelay & relay, int64_t now);
std::vector<live_location::Outcome> Online(live_location::Joiner & joiner, ModelRelay & relay, int64_t now);

std::unique_ptr<live_location::Joiner> JoinerStarts(std::string const & link, std::string const & name,
                                                    ModelRelay & relay, int64_t now);

struct Paired
{
  live_location::ContactPtr m_inviterSide;  // the inviter's contact for the joiner
  live_location::ContactPtr m_joinerSide;   // the joiner's contact for the inviter
  std::shared_ptr<ModelRelay> m_relay;
  std::shared_ptr<live_location::Inviter> m_inviter;
  std::shared_ptr<live_location::Joiner> m_joiner;
  std::string m_link;
};

/// A complete pairing over a model relay, with the checks of the Python pair() when `checksOn`. Unless
/// checks are on, the joiner's confirmation is not delivered, so the inviter's contact stays waiting.
Paired Pair(std::string const & inviterName, live_location::Relays const & inviterRelays,
            std::string const & joinerName, live_location::Relays const & joinerRelays, int64_t now,
            bool checksOn = true);

/// The states from `contact` that an app reading its inbox relay at `now` accepts.
std::vector<live_location::State> ReadInbox(live_location::Contact & contact, ModelRelay const & relay, int64_t now);

/// Every viewer reads every state, as if all used one relay; each keeps what it can read.
void Deliver(std::vector<std::pair<live_location::ContactPtr, live_location::nostr::Event>> const & states,
             std::vector<std::pair<live_location::ContactPtr, live_location::Following *>> const & views, int64_t now);

/// A position at `now`, as in the Python suite.
live_location::Location Fix(int64_t now);

template <typename Exception, typename F>
bool Throws(F && f)
{
  try
  {
    f();
  }
  catch (Exception const &)
  {
    return true;
  }
  catch (...)
  {
    return false;
  }
  return false;
}
}  // namespace live_location_tests
