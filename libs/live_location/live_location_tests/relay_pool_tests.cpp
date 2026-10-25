#include "testing/testing.hpp"

#include "live_location/live_location_tests/fake_relay.hpp"
#include "live_location/live_location_tests/scenario.hpp"

#include "live_location/crypto/schnorr.hpp"
#include "live_location/nostr/relay_message.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/relay/relay_pool.hpp"

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <vector>

// The relay pool against in-process relays: delivery with relays down, dead connections, deduplication,
// the listening relay moving and coming back, relays that answer only in part, the echo check, scopes,
// lingering connections and relay consent.
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

UNIT_TEST(RelayPool_SaysWhenAConnectionOpens)
{
  Harness h;
  std::vector<std::string> opened;
  h.m_pool.OnConnected([&](std::string const & url) { opened.push_back(url); });
  h.Relay(kR1).SetDown(true);
  h.m_pool.Publish(EpochScope(1), {kR1, kR2}, h.Event());
  h.m_executor.RunFor(1000);
  TEST(opened == std::vector<std::string>{kR2}, ("not a relay that could not be reached"));

  // The relay is back (or the phone's network): a subscription that waited for it connects, which is said too.
  h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); }, [](nostr::Event const &) {});
  h.Relay(kR1).SetDown(false);
  h.m_executor.RunFor(10'000);
  TEST(opened == (std::vector<std::string>{kR2, kR1}), ());
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

UNIT_TEST(RelayPool_AnEventPublishedAgainOnItsWayWaitsForTheSameOk)
{
  Harness h;
  std::vector<bool> first;
  std::vector<bool> second;
  nostr::Event const event = h.Event();
  h.m_pool.Publish(EpochScope(1), kThree, event, [&](bool delivered) { first.push_back(delivered); });
  h.m_pool.Publish(EpochScope(1), kThree, event, [&](bool delivered) { second.push_back(delivered); });
  h.m_executor.RunFor(1000);
  TEST(first == std::vector<bool>{true} && second == std::vector<bool>{true}, ("both answered by its OK"));
  TEST(!h.m_pool.HasPendingPublications(), ());
  for (auto const & url : kThree)
    TEST_EQUAL(CountType(h.Relay(url), "EVENT"), 1, ("sent once", url));
  h.m_executor.RunFor(12'000);
  TEST_EQUAL(h.m_pool.Connections().size(), 3, ("no connection waits for an OK that came, and fails for it"));

  // Over a dead connection, both fail with it, once.
  h.Relay(kR1).m_silent = true;
  first.clear();
  second.clear();
  nostr::Event const other = h.Event(kKindStored, "other");
  h.m_pool.Publish(EpochScope(1), {kR1}, other, [&](bool delivered) { first.push_back(delivered); });
  h.m_executor.RunFor(5'000);
  h.m_pool.Publish(EpochScope(1), {kR1}, other, [&](bool delivered) { second.push_back(delivered); });
  h.m_executor.RunFor(5'100);
  TEST(first == std::vector<bool>{false} && second == std::vector<bool>{false}, ());
  TEST(!h.m_pool.HasPendingPublications() && h.m_pool.IsFailing(kR1), ());
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

UNIT_TEST(RelayPool_ABrokenCopyDoesNotHideTheIntactOne)
{
  Harness h;
  std::vector<nostr::Event> received;
  h.m_pool.Subscribe(EpochScope(1), kThree, Placement::All, [&] { return h.Filters(); },
                     [&](nostr::Event const & event) { received.push_back(event); });
  h.m_executor.RunFor(1000);

  // r1 lies, and its copy arrives first.
  h.Relay(kR1).m_forge = true;
  h.Relay(kR1).m_latencyMs = 5;
  nostr::Event const event = h.Event();
  for (auto const & url : kThree)
    h.Relay(url).Inject(event);
  h.m_executor.RunFor(1000);
  TEST_EQUAL(received.size(), 1, ());
  TEST_EQUAL(received[0].m_sig, event.m_sig, ("the intact copy, from the honest relays"));

  // Altered content under the event's id: the same.
  h.Relay(kR1).m_forge = false;
  nostr::Event const second = h.Event(kKindStored, "second");
  nostr::Event altered = second;
  altered.m_content = "altered";
  h.Relay(kR1).Push(altered);
  h.m_executor.RunFor(100);
  h.Relay(kR2).Inject(second);
  h.m_executor.RunFor(1000);
  TEST(received.size() == 2 && received[1].m_content == "second", ());
}

UNIT_TEST(RelayPool_EventsNotAskedForAreDroppedAndAFloodFailsTheRelay)
{
  Harness h;
  std::vector<std::string> received;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::All, [&] { return h.Filters(); },
                                     [&](nostr::Event const & event) { received.push_back(event.m_id); });
  h.m_executor.RunFor(1000);

  // Validly signed, but by someone the REQ did not ask for.
  int64_t const now = h.m_executor.Now();
  nostr::Event const stranger = SignEvent(RandomSecpKey(ScenarioRng()), now, kKindStored,
                                          {{"d", ""}, {"expiration", std::to_string(now + 900)}}, "x", ScenarioRng());
  h.Relay(kR1).Push(stranger);
  h.m_executor.RunFor(1000);
  TEST(received.empty(), ("not asked for"));
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 3, ("one is not enough to fail a relay"));

  // A flood of broken events: r1 counts as failing; the others carry on.
  h.Relay(kR1).m_forge = true;
  for (int i = 0; i < 40; ++i)
    h.Relay(kR1).Push(h.Event(kKindStored, "junk " + std::to_string(i)));
  h.m_executor.RunFor(500);
  TEST(received.empty(), ());
  auto const placement = h.m_pool.PlacementOf(id);
  TEST(placement.size() == 2 && std::find(placement.begin(), placement.end(), kR1) == placement.end(), (placement));
  nostr::Event const event = h.Event(kKindStored, "intact");
  h.Relay(kR2).Inject(event);
  h.m_executor.RunFor(1000);
  TEST(received == std::vector<std::string>{event.m_id}, ());
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

UNIT_TEST(RelayPool_AReqWithoutItsEoseFailsTheRelay)
{
  Harness h;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());

  // r1 still answers publishes, but no longer finishes answering a REQ: the next one, over the open
  // connection, never ends. Nothing then tells whether r1 delivers, so the listening REQ moves too.
  h.Relay(kR1).m_noEose = true;
  auto const other = h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); },
                                        [](nostr::Event const &) {});
  h.m_executor.RunFor(14'500);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ("not before the deadline"));
  h.m_executor.RunFor(1'000);
  TEST(h.m_pool.IsFailing(kR1), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ());
  h.m_pool.Unsubscribe(other);

  // It is tried again as each back-off ends, and fails again; its OKs meanwhile do not cut the next
  // back-off short: about ten connections in ten minutes, not one every 16 s.
  size_t const attempts = h.m_transport.m_attempts[kR1];
  size_t const oks = CountType(h.Relay(kR1), "EVENT");
  for (int i = 0; i < 120; ++i)
  {
    h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, std::to_string(i)));
    h.m_executor.RunFor(5'000);
  }
  TEST_GREATER(CountType(h.Relay(kR1), "EVENT"), oks, ("published to while it is not failing"));
  TEST_GREATER(h.m_transport.m_attempts[kR1] - attempts, 3, ());
  TEST_LESS(h.m_transport.m_attempts[kR1] - attempts, 12, ());

  // Answering again, it is the listening relay again. A REQ sent again that it leaves unanswered fails it
  // the same way.
  h.Relay(kR1).m_noEose = false;
  h.m_executor.RunFor(400'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
  TEST(!h.m_pool.IsFailing(kR1), ());
  h.Relay(kR1).m_noEose = true;
  h.m_pool.Refresh(id);
  h.m_executor.RunFor(15'500);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ());
}

UNIT_TEST(RelayPool_ARelayThatDropsEveryConnectionBacksOffFurther)
{
  Harness h;
  h.Relay(kR1).m_dropOnOpen = true;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(600'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ());
  TEST_LESS(h.m_transport.m_attempts[kR1], 12, ("from 1 s doubling to 5 min, not every second"));

  // A connection that stays and answers starts its back-off over: a drop is retried after a second again.
  h.Relay(kR1).m_dropOnOpen = false;
  h.m_executor.RunFor(400'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
  h.Relay(kR1).DropConnections();
  h.m_executor.RunFor(200);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ());
  h.m_executor.RunFor(3'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
}

UNIT_TEST(RelayPool_ARelayThatAnswersNoPublishKeepsBackingOff)
{
  // The reverse: r1 answers REQs, but no publish, and its EOSEs do not cut the back-off short.
  Harness h;
  h.Relay(kR1).m_noOk = true;
  h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); }, [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  for (int i = 0; i < 120; ++i)
  {
    h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(kKindStored, std::to_string(i)));
    h.m_executor.RunFor(5'000);
  }
  TEST_GREATER(h.m_transport.m_attempts[kR1], 4, ());
  TEST_LESS(h.m_transport.m_attempts[kR1], 12, ());
}

UNIT_TEST(RelayPool_AnAnswerStartsTheBackOffOver)
{
  // r1 drops a connection, then answers a publish: its next drop is retried after a second again, not two.
  Harness h;
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event());
  h.m_executor.RunFor(1000);
  h.Relay(kR1).DropConnections();
  h.m_executor.RunFor(5'000);
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(kKindStored, "second"));
  h.m_executor.RunFor(1000);
  TEST(!h.m_pool.IsFailing(kR1), ());
  h.Relay(kR1).DropConnections();
  h.m_executor.RunFor(100);
  TEST(h.m_pool.IsFailing(kR1), ());
  h.m_executor.RunFor(1'300);
  TEST(!h.m_pool.IsFailing(kR1), ());
}

UNIT_TEST(RelayPool_TheListeningRelayMovesWhenItStopsDelivering)
{
  Harness h;
  std::vector<std::string> received;
  // A listening REQ that asks for this client's own events, as a sharer's does (the echo check).
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [&](nostr::Event const & event) { received.push_back(event.m_id); });
  h.m_executor.RunFor(1000);
  auto const publish = [&]
  { h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, std::to_string(h.m_executor.NowMs()))); };

  publish();
  h.m_executor.RunFor(20'000);
  TEST_EQUAL(received.size(), 1, ("an event coming back is delivered like any other"));
  TEST(!h.m_pool.IsDeaf(kR1), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());

  // r1 still accepts events, but its delivery broke: one miss moves the listening REQ, within 15 s.
  h.Relay(kR1).m_deaf = true;
  publish();
  h.m_executor.RunFor(14'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ("not before the timeout"));
  h.m_executor.RunFor(2'000);
  TEST(h.m_pool.IsDeaf(kR1), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ("moved to the next relay"));
  TEST(h.m_pool.FirstReachable(kThree) == std::optional<std::string>(kR2), ());
  size_t const sent = CountType(h.Relay(kR1), "EVENT");
  publish();
  h.m_executor.RunFor(1'000);
  TEST_EQUAL(CountType(h.Relay(kR1), "EVENT"), sent + 1, ("publishing to it goes on"));

  // After its back-off (5 min, +-20 %) it is tried again, next to r2; still deaf, its back-off doubles.
  h.m_executor.RunFor(360'000);
  TEST(h.m_pool.PlacementOf(id) == (std::vector<std::string>{kR1, kR2}), ("tried again, alongside"));
  publish();
  h.m_executor.RunFor(16'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ());
  h.m_executor.RunFor(400'000);
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR2}, ("a longer back-off"));

  // Delivering again: once an event comes back over it, the only listening relay again.
  h.Relay(kR1).m_deaf = false;
  h.m_executor.RunFor(400'000);
  TEST(h.m_pool.PlacementOf(id) == (std::vector<std::string>{kR1, kR2}), ());
  // Over the connections already open: no relay connecting again moves the subscription meanwhile. r2's
  // copy arrives first; r1's still counts.
  h.Relay(kR1).m_latencyMs = 200;
  h.m_pool.Publish(EpochScope(1), {kR1, kR2}, h.Event(kKindStored, "recovered"));
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ());
  TEST(!h.m_pool.IsDeaf(kR2), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
}

UNIT_TEST(RelayPool_TheEchoCheckJudgesOnlyWhatMustComeBack)
{
  Harness h;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);

  // A relay that has never sent an event back is not judged: some might never do so.
  h.Relay(kR1).m_noEcho = true;
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "first"));
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
  h.Relay(kR1).m_noEcho = false;
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "second"));
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ("it echoes now"));

  // An event it already had, and one it refused, come back to no one.
  nostr::Event const event = h.Event(kKindStored, "third");
  h.m_pool.Publish(EpochScope(1), kThree, event);
  h.m_executor.RunFor(20'000);
  h.m_pool.Publish(EpochScope(1), kThree, event);
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ("a duplicate"));
  h.Relay(kR1).m_refuse = true;
  h.m_pool.Publish(EpochScope(1), kThree, h.Event(kKindStored, "fourth"));
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ("a refusal"));
  h.Relay(kR1).m_refuse = false;

  // Nor what a REQ sent again no longer asks for, nor events published before the REQ's EOSE.
  Key const other = RandomSecpKey(ScenarioRng());
  std::string const otherPk = ToHex(crypto::GetXOnlyPublicKey(other));
  std::vector<nostr::Filter> filters = h.Filters();
  auto const id2 = h.m_pool.Subscribe(EpochScope(2), {kR2}, Placement::FirstReachable, [&] { return filters; },
                                      [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  h.m_pool.Publish(EpochScope(2), {kR2}, h.Event(kKindStored, "echoed"));
  h.m_executor.RunFor(1000);
  h.Relay(kR2).m_deaf = true;
  h.m_pool.Publish(EpochScope(2), {kR2}, h.Event(kKindStored, "fifth"));
  filters = {{{kKindStored}, {otherPk}, {}, {}}};
  h.m_pool.Refresh(id2);
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR2), ("asked for by the old filters only"));
  filters = h.Filters();
  h.m_pool.Refresh(id2);
  h.m_pool.Publish(EpochScope(2), {kR2}, h.Event(kKindStored, "sixth"));
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR2), ("published before the EOSE of the REQ sent again"));
}

UNIT_TEST(RelayPool_OnlyAnIntactCopyCountsAsSentBack)
{
  Harness h;
  std::vector<std::string> echoed;
  h.m_pool.OnEchoed([&](std::string const & url) { echoed.push_back(url); });
  Key const other = RandomSecpKey(ScenarioRng());
  std::vector<nostr::Filter> filters = {{{kKindStored}, {ToHex(crypto::GetXOnlyPublicKey(other))}, {}, {}}};
  auto const id = h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::FirstReachable, [&] { return filters; },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);

  // A copy the REQ did not ask for, which only a relay that sends anything would send.
  nostr::Event const event = h.Event();
  h.m_pool.Publish(EpochScope(1), {kR1}, event);
  h.m_executor.RunFor(1000);
  h.Relay(kR1).Push(event);
  h.m_executor.RunFor(1000);
  TEST(echoed.empty(), ("not asked for"));

  filters = h.Filters();
  h.m_pool.Refresh(id);
  h.m_executor.RunFor(1000);
  h.Relay(kR1).m_forge = true;
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(kKindStored, "first"));
  h.m_executor.RunFor(20'000);
  TEST(echoed.empty(), ("a broken copy shows nothing"));
  h.Relay(kR1).m_forge = false;
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event(kKindStored, "second"));
  h.m_executor.RunFor(20'000);
  TEST(echoed == std::vector<std::string>{kR1}, ());
}

UNIT_TEST(RelayPool_AnEventSentAgainIsNotJudged)
{
  // r1 accepts an event it already keeps with an empty message, as NIP-01 allows, and does not deliver
  // it again.
  Harness h;
  h.m_pool.SetEchoing({kR1});
  h.Relay(kR1).m_plainDuplicate = true;

  // A pairing step sent again after its OK was lost with the connection: over a new connection, which
  // could not tell. A pairing's REQ asks for its own steps too, but only a listening REQ judges.
  h.m_pool.Subscribe(PairingScope("p"), {kR1}, Placement::All, [&] { return h.Filters(); },
                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  nostr::Event const step = h.Event();
  h.m_pool.Publish(PairingScope("p"), {kR1}, step);
  h.m_executor.RunFor(20'000);
  h.Relay(kR1).DropConnections();
  h.m_executor.RunFor(5'000);
  TEST_EQUAL(h.Relay(kR1).OpenConnections(), 1, ("connected again"));
  h.m_pool.Publish(PairingScope("p"), {kR1}, step);
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ());

  // On a listening REQ, an event sent again over the connection that sent it: the same.
  auto const id = h.m_pool.Subscribe(EpochScope(1), {kR1, kR2}, Placement::FirstReachable, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  nostr::Event const event = h.Event(kKindStored, "listening");
  h.m_pool.Publish(EpochScope(1), {kR1}, event);
  h.m_executor.RunFor(20'000);
  h.m_pool.Publish(EpochScope(1), {kR1}, event);
  h.m_executor.RunFor(20'000);
  TEST(!h.m_pool.IsDeaf(kR1), ());
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());
}

UNIT_TEST(RelayPool_ARefreshedReqMayStillBeAnsweredForItsOldFilters)
{
  Harness h;
  Key const other = RandomSecpKey(ScenarioRng());
  std::string const otherPk = ToHex(crypto::GetXOnlyPublicKey(other));
  std::vector<nostr::Filter> filters = h.Filters();
  std::vector<std::string> received;
  auto const id = h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return filters; },
                                     [&](nostr::Event const & event) { received.push_back(event.m_id); });
  h.m_executor.RunFor(1000);

  // The relay delivers for the old filters until the new REQ reaches it: more than a failing relay
  // could send, and none of it is held against the relay or passed on.
  filters = {{{kKindStored}, {otherPk}, {}, {}}};
  h.m_pool.Refresh(id);
  for (int i = 0; i < 40; ++i)
    h.Relay(kR1).Inject(h.Event(kKindStored, "old " + std::to_string(i)));
  h.m_executor.RunFor(1000);
  TEST(received.empty(), ());
  TEST_EQUAL(h.m_transport.m_attempts[kR1], 1, ("not failed"));
  TEST(h.m_pool.PlacementOf(id) == std::vector<std::string>{kR1}, ());

  // After the EOSE, the old filters are over.
  int64_t const now = h.m_executor.Now();
  nostr::Event const wanted =
      SignEvent(other, now, kKindStored, {{"d", ""}, {"expiration", std::to_string(now + 900)}}, "new", ScenarioRng());
  h.Relay(kR1).Inject(wanted);
  h.m_executor.RunFor(1000);
  TEST(received == std::vector<std::string>{wanted.m_id}, ());
  for (int i = 0; i < 40; ++i)
    h.Relay(kR1).Push(h.Event(kKindStored, "late " + std::to_string(i)));
  h.m_executor.RunFor(200);
  TEST(h.m_pool.IsFailing(kR1), ("these count"));
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

UNIT_TEST(RelayPool_ASubscriptionEndedBeforeItsConnectionOpensIsNeverSent)
{
  Harness h;
  auto const id = h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  h.m_pool.Unsubscribe(id);
  h.m_executor.RunFor(1000);
  TEST_EQUAL(CountType(h.Relay(kR1), "REQ"), 0, ("no REQ the relay would keep answering"));
  h.m_executor.RunFor(60'000);
  TEST(h.m_pool.Connections().empty(), ());
}

UNIT_TEST(RelayPool_NoticesDoNotKeepAConnectionOpen)
{
  Harness h;
  h.m_pool.Publish(EpochScope(1), {kR1}, h.Event());
  for (int i = 0; i < 4; ++i)
  {
    h.m_executor.RunFor(20'000);
    h.Relay(kR1).Broadcast(R"(["NOTICE","hello"])");
  }
  TEST(h.m_pool.Connections().empty(), ("closed a minute after its OK"));
}

UNIT_TEST(RelayPool_EventsForNoReqCountAgainstTheRelay)
{
  Harness h;
  auto const id = h.m_pool.Subscribe(EpochScope(1), kThree, Placement::All, [&] { return h.Filters(); },
                                     [](nostr::Event const &) {});
  auto const closed = h.m_pool.Subscribe(EpochScope(1), {kR1}, Placement::All, [&] { return h.Filters(); },
                                         [](nostr::Event const &) {});
  h.m_executor.RunFor(1000);
  std::vector<std::string> reqIds;
  for (auto const & [link, messages] : h.Relay(kR1).m_received)
    for (auto const & message : messages)
      if (message.rfind("[\"REQ\"", 0) == 0)
        reqIds.push_back(message.substr(8, 16));
  TEST_EQUAL(reqIds.size(), 2, ());
  auto const send = [&](std::string const & reqId)
  {
    for (int i = 0; i < 40; ++i)
    {
      nostr::Event const event = h.Event(kKindStored, reqId + std::to_string(i));
      h.Relay(kR1).Broadcast(R"(["EVENT",")" + reqId + R"(",)" + nostr::ToJson(event) + "]");
    }
    h.m_executor.RunFor(500);
  };

  // Events for a REQ just closed, sent before the relay had the CLOSE: not held against it.
  h.m_pool.Unsubscribe(closed);
  send(reqIds[1]);
  TEST(!h.m_pool.IsFailing(kR1), ());
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 3, ());

  // Events for a REQ never sent are junk.
  send("0123456789abcdef");
  TEST(h.m_pool.IsFailing(kR1), ());
  TEST_EQUAL(h.m_pool.PlacementOf(id).size(), 2, ());
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
