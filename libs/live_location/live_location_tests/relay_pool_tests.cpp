#include "testing/testing.hpp"

#include "live_location/live_location_tests/fake_relay.hpp"
#include "live_location/live_location_tests/scenario.hpp"

#include "live_location/nostr/relay_message.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/relay/relay_pool.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

// The relay pool against in-process relays: delivery with relays down, dead connections, deduplication,
// the listening relay moving and coming back, scopes, lingering connections and relay consent.
namespace relay_pool_tests
{
using namespace live_location;
using namespace live_location::relay;
using namespace live_location_tests;

std::string const kR1 = "wss://r1.example";
std::string const kR2 = "wss://r2.example";
std::string const kR3 = "wss://r3.example";
Relays const kThree = {kR1, kR2, kR3};

struct Harness
{
  explicit Harness(RelayPool::AllowFn allow = [](std::string const &) { return true; })
    : m_executor(kT0 * 1000)
    , m_transport(m_executor)
    , m_pool(m_transport, m_executor, ScenarioRng(), std::move(allow))
  {
    for (auto const & url : kThree)
      m_transport.Add(url);
  }

  FakeRelay & Relay(std::string const & url) { return *m_transport.Find(url); }

  nostr::Event Event(int64_t kind = kKindStored, std::string content = "x")
  {
    int64_t const now = m_executor.Now();
    nostr::Tags tags = {{"d", ""}, {"expiration", std::to_string(now + 900)}};
    if (kind == kKindSignal)
      tags.clear();
    return SignEvent(m_key, now, kind, std::move(tags), std::move(content), ScenarioRng());
  }

  std::vector<nostr::Filter> Filters() const { return {{{kKindStored, kKindSignal}, {m_pubkey}, {}, {}}}; }

  VirtualExecutor m_executor;
  FakeTransport m_transport;
  RelayPool m_pool;
  Key const m_key = RandomSecpKey(ScenarioRng());
  std::string const m_pubkey = ToHex(crypto::GetXOnlyPublicKey(m_key));
};

size_t CountType(FakeRelay const & relay, std::string const & type)
{
  size_t n = 0;
  for (auto const & entry : relay.m_received)
    for (auto const & message : entry.second)
      n += message.rfind("[\"" + type + "\"", 0) == 0 ? 1 : 0;
  return n;
}

UNIT_TEST(RelayPool_PublishesWithRelaysDown)
{
  Harness h;
  std::vector<bool> results;
  auto const record = [&](bool delivered) { results.push_back(delivered); };

  h.m_pool.Publish(EpochScope(1), kThree, h.Event(), record);
  h.m_executor.RunFor(1000);
  TEST(results == std::vector<bool>{true}, ("delivered once, on the first OK"));
  for (auto const & url : kThree)
    TEST_EQUAL(h.Relay(url).Stored().size(), 1, (url));

  // Two of three relays down: one OK is enough.
  h.Relay(kR1).SetDown(true);
  h.Relay(kR2).SetDown(true);
  h.m_executor.RunFor(100);  // the pool learns that their connections dropped
  TEST(h.m_pool.IsFailing(kR1) && h.m_pool.IsFailing(kR2) && !h.m_pool.IsFailing(kR3),
       ("relays that dropped their connections back off"));
  size_t const attempts = h.m_transport.m_attempts[kR1];
  results.clear();
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "y"), record);
  h.m_executor.RunFor(500);
  TEST(results == std::vector<bool>{true} && h.m_transport.m_attempts[kR1] == attempts,
       ("delivered by the third relay; the failing ones are skipped while they back off"));
  h.m_executor.RunFor(2'000);  // past the back-off
  results.clear();
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "z"), record);
  h.m_executor.RunFor(1000);
  TEST(results == std::vector<bool>{true} && h.m_transport.m_attempts[kR1] == attempts + 1 && h.m_pool.IsFailing(kR1),
       ("tried again once the back-off is over, and failing again"));

  // Every relay down: not delivered, reported once.
  h.Relay(kR3).SetDown(true);
  h.m_executor.RunFor(1000);
  results.clear();
  h.m_pool.Publish(EpochScope(1), {kR3}, h.Event(kKindStored, "w"), record);
  h.m_executor.RunFor(20'000);
  TEST(results == std::vector<bool>{false}, ("nothing accepted it"));

  // The relays come back; once the back-off is over they are used again.
  for (auto const & url : kThree)
    h.Relay(url).SetDown(false);
  h.m_executor.RunFor(400'000);
  results.clear();
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "v"), record);
  h.m_executor.RunFor(1000);
  TEST(results == std::vector<bool>{true} && !h.m_pool.IsFailing(kR1) && !h.m_pool.IsFailing(kR2), ());
}

UNIT_TEST(RelayPool_DeadConnectionIsDetectedByTheMissingOk)
{
  Harness h;
  std::vector<bool> results;
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(), [&](bool delivered) { results.push_back(delivered); });
  h.m_executor.RunFor(1000);
  TEST(results == std::vector<bool>{true}, ());
  TEST_EQUAL(h.Relay(kR1).OpenConnections(), 1, ("the connection lingers"));

  // The connection dies silently (e.g. a NAT timeout): the relay never answers again.
  h.Relay(kR1).m_silent = true;
  results.clear();
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(kKindStored, "y"),
                   [&](bool delivered) { results.push_back(delivered); });
  h.m_executor.RunFor(9'900);
  TEST(results.empty(), ("still waiting for the OK"));
  h.m_executor.RunFor(200);
  TEST(results == std::vector<bool>{false} && h.m_pool.IsFailing(kR1) && h.m_pool.Connections().empty(),
       ("no OK in 10 s: the publish failed, the connection is closed and the relay backs off"));
}

UNIT_TEST(RelayPool_SubscriptionsDeduplicateAndSurviveRestarts)
{
  Harness h;
  std::vector<std::string> received;
  size_t eoses = 0;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::All, [&] { return h.Filters(); },
                                     [&](nostr::Event const & event) { received.push_back(event.m_id); },
                                     [&](std::string const &) { ++eoses; });
  h.m_executor.RunFor(1000);
  TEST_EQUAL(eoses, 3, ("every relay answers with EOSE"));
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 3, ());

  h.Relay(kR2).m_duplicate = true;
  nostr::Event const first = h.Event();
  for (auto const & url : kThree)
    h.Relay(url).Inject(first);
  h.m_executor.RunFor(1000);
  TEST(received == std::vector<std::string>{first.m_id}, ("an event from three relays, one twice, arrives once"));

  // A relay restarts: the subscription comes back on it after the back-off, and receives what follows.
  h.Relay(kR1).DropConnections();
  h.m_executor.RunFor(500);
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 2, ("off the restarted relay while it backs off"));
  h.m_executor.RunFor(3'000);
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 3, ("back on it"));
  nostr::Event const second = h.Event(kKindStored, "second");
  h.Relay(kR1).Inject(second);
  h.m_executor.RunFor(1000);
  TEST(received.size() == 2 && received[1] == second.m_id, ("received over the new connection"));

  // A relay closes the subscription (e.g. rate limiting): it is sent again 30 s later.
  auto const reqs = CountType(h.Relay(kR3), "REQ");
  h.Relay(kR3).CloseSubscriptions("rate-limited: slow down");
  h.m_executor.RunFor(1000);
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 2, ("off the relay that closed it"));
  TEST_EQUAL(CountType(h.Relay(kR3), "REQ"), reqs, ());
  h.m_executor.RunFor(30'000);
  TEST(CountType(h.Relay(kR3), "REQ") == reqs + 1 && h.m_pool.PlacementOf(id).size() == 3, ("sent again"));

  h.m_pool.Unsubscribe(id);
  h.m_executor.RunFor(100);
  TEST_GREATER(CountType(h.Relay(kR2), "CLOSE"), 0, ("unsubscribing sends CLOSE"));
  h.m_executor.RunFor(61'000);
  TEST(h.m_pool.Connections().empty(), ("without subscriptions, connections close after a minute without traffic"));
}

UNIT_TEST(RelayPool_ListeningRelayMovesAndComesBack)
{
  Harness h;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ("on the first relay only"));
  TEST(h.m_pool.Connections().size() == 1, ("one connection while listening"));

  h.Relay(kR1).SetDown(true);
  h.m_executor.RunFor(200);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ("moved to the next relay"));
  h.Relay(kR2).SetDown(true);
  h.m_executor.RunFor(200);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR3}, ("and the next"));

  h.Relay(kR1).SetDown(false);
  h.m_executor.RunFor(30'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ("back on the first relay after its back-off"));
  h.m_executor.RunFor(61'000);
  auto const connections = h.m_pool.Connections();
  TEST(connections.size() == 1 && connections[0].first == kR1, ("the other connections closed"));
}

UNIT_TEST(RelayPool_ScopesNeverShareAConnection)
{
  Harness h;
  h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); }, [](nostr::Event const &) {});
  h.m_pool.Publish(EpochScope(2), {kR1}, h.Event());
  h.m_pool.Publish(PairingScope("abc"), {kR1}, h.Event(kKindStored, "pairing"));
  h.m_executor.RunFor(1000);
  auto const & received = h.Relay(kR1).m_received;
  TEST_EQUAL(received.size(), 3, ("three scopes, three connections"));
  for (auto const & [link, messages] : received)
    TEST_EQUAL(messages.size(), 1, ("one message per connection here"));

  // REQ ids are random per REQ, so they cannot link connections.
  h.m_pool.Subscribe(EpochScope(3), {kR1}, Placement::All, [&] { return h.Filters(); }, [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  std::set<std::string> ids;
  for (auto const & [link, messages] : h.Relay(kR1).m_received)
    for (auto const & message : messages)
      if (message.rfind("[\"REQ\"", 0) == 0)
        ids.insert(message.substr(8, 16));
  TEST_EQUAL(ids.size(), 2, ());
}

UNIT_TEST(RelayPool_RelayConsentIsEnforced)
{
  Harness h([](std::string const & url) { return url != kR2; });
  h.m_pool.Subscribe(EpochScope(1), kThree, Placement::All, [&] { return h.Filters(); }, [](nostr::Event const &) {});
  h.m_pool.Publish(EpochScope(1), kThree, h.Event());
  h.m_executor.RunFor(1000);
  TEST_EQUAL(h.m_transport.m_attempts.count(kR2), 0, ("never connects to a relay the user has not allowed"));
  TEST(h.m_pool.FirstReachable({kR2, kR3}) == std::optional<std::string>(kR3), ());
}

UNIT_TEST(RelayPool_MalformedMessagesAreIgnored)
{
  for (std::string const text : {"", "[]", "{}", "[\"EVENT\"]", "[\"OK\",\"x\",\"true\"]",
                                 "[\"EVENT\",\"s\",{\"id\":5}]", "[\"AUTH\",\"c\"]", "[\"EOSE\",5]", "not json"})
  {
    auto const message = nostr::ParseRelayMessage(text);
    TEST(!message || (message->m_type == nostr::RelayMessage::Type::Event && !message->m_event), (text));
  }
  auto const ok = nostr::ParseRelayMessage(R"(["OK","ab",true,"duplicate: have it"])");
  TEST(ok && ok->m_type == nostr::RelayMessage::Type::Ok && ok->m_accepted && ok->m_eventId == "ab", ());
  TEST(!nostr::ParseRelayMessage(std::string(nostr::kMaxRelayMessage + 1, ' ')), ("oversized"));
  TEST(nostr::ParseRelayMessage(R"(["NOTICE","a","b"])"), ());
  TEST(nostr::ParseRelayMessage(R"(["OK","ab",true,"m","extra"])"), ("extra elements are fine"));
  TEST(!nostr::ParseRelayMessage(R"({"OK":1,"OK":2})"), ("duplicates refused"));
}
}  // namespace relay_pool_tests
