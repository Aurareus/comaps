#include "testing/testing.hpp"

#include "live_location/live_location_tests/fake_relay.hpp"
#include "live_location/live_location_tests/scenario.hpp"

#include "live_location/manager/manager.hpp"
#include "live_location/manager/marks.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/store/store.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Whole phones against in-process relays: pairing, sharing, live updates, relays down, time limits,
// revocation, the connection policy, relay consent, restarts, the store's key rotation, dot colours and
// the battery.
namespace manager_tests
{
using namespace live_location;
using namespace live_location_tests;

struct Recorder : public ManagerListener
{
  void OnContacts(std::vector<ContactInfo> const & contacts) override { m_contacts = contacts; }
  void OnPairing(PairingInfo const & pairing) override { m_pairings[pairing.m_id] = pairing; }
  void OnPositions(std::vector<PositionInfo> const & positions) override
  {
    m_positions = positions;
    ++m_positionUpdates;
  }
  void OnSharing(SharingInfo const & sharing) override { m_sharing = sharing; }
  void OnConsentNeeded(ConsentRequest const & request) override { m_consents.push_back(request); }
  void OnLocationRequest(LocationRequest request) override { m_location = request; }
  void OnStoreError() override { ++m_storeErrors; }
  void OnWriteFailed() override { ++m_writeFailures; }

  std::vector<ContactInfo> m_contacts;
  std::map<std::string, PairingInfo> m_pairings;
  std::vector<PositionInfo> m_positions;
  size_t m_positionUpdates = 0;
  SharingInfo m_sharing;
  std::vector<ConsentRequest> m_consents;
  LocationRequest m_location = LocationRequest::Off;
  int m_storeErrors = 0;
  int m_writeFailures = 0;
};

class World;

/// The platform key store, which can fail for a while.
class TestKeys : public store::InsecureKeyWrapper
{
public:
  std::optional<Wrapped> Wrap(Key const & dataKey) override
  {
    if (m_failing)
      return {};
    return InsecureKeyWrapper::Wrap(dataKey);
  }
  std::optional<Key> Unwrap(Wrapped const & wrapped) override
  {
    if (m_failing)
      return {};
    return InsecureKeyWrapper::Unwrap(wrapped);
  }

  bool m_failing = false;
};

/// One phone: a manager with its own store, key store and randomness.
class Phone
{
public:
  Phone(World & world, std::string const & name);
  ~Phone();

  /// The process dies and starts again from its store. False when the store cannot be read.
  bool Restart(bool expectReadable = true);

  Manager & M() { return *m_manager; }
  Recorder & Events() { return m_events; }
  std::string const & Path() const { return m_path; }
  TestKeys & Keys() { return m_keys; }

  ContactInfo const * Contact(std::string const & name) const
  {
    for (auto const & contact : m_events.m_contacts)
      if (contact.m_name == name)
        return &contact;
    return nullptr;
  }
  PositionInfo const * Position(std::string const & name) const
  {
    for (auto const & position : m_events.m_positions)
      if (position.m_name == name)
        return &position;
    return nullptr;
  }
  std::string Id(std::string const & name) const { return Contact(name) ? Contact(name)->m_id : std::string(); }

private:
  World & m_world;
  std::string m_path;
  crypto::TestRng m_rng;
  TestKeys m_keys;
  Recorder m_events;
  std::unique_ptr<store::Store> m_store;
  std::unique_ptr<Manager> m_manager;
};

class World
{
public:
  World() : m_executor(kT0 * 1000), m_transport(m_executor)
  {
    for (auto const & url : kDefaultRelays)
      m_transport.Add(std::string(url));
  }

  void Run(int64_t ms) { m_executor.RunFor(ms); }
  FakeRelay & Relay(std::string const & url) { return *m_transport.Find(url); }

  VirtualExecutor m_executor;
  FakeTransport m_transport;
};

Phone::Phone(World & world, std::string const & name)
  : m_world(world)
  , m_path((std::filesystem::temp_directory_path() / ("nll_manager_" + name + ".dat")).string())
  , m_rng(AsBytes("phone " + name))
{
  std::remove(m_path.c_str());
  Restart();
  TEST(m_manager->SetName(name), ());
}

Phone::~Phone()
{
  m_manager.reset();
  std::remove(m_path.c_str());
}

bool Phone::Restart(bool expectReadable)
{
  m_manager.reset();
  m_store = std::make_unique<store::Store>(m_path, m_keys, m_rng);
  m_manager = std::make_unique<Manager>(m_world.m_executor, m_world.m_transport, *m_store, m_rng, m_events);
  bool const started = m_manager->Start();
  if (expectReadable)
    TEST(started, ());
  return started;
}

double FromBits(uint64_t bits)
{
  double d;
  std::memcpy(&d, &bits, sizeof(d));
  return d;
}

Location FixAt(World & world, double lat, double lon)
{
  Location fix;
  fix.m_ts = world.m_executor.NowMs();
  fix.m_lat = lat;
  fix.m_lon = lon;
  fix.m_acc = 5;
  return fix;
}

/// A pairing by QR code, both apps open, codes compared on both sides. Relays the joiner is asked
/// about are refused.
void Pair(World & world, Phone & inviter, Phone & joiner)
{
  inviter.M().SetForeground(true);
  joiner.M().SetForeground(true);
  auto const invite = inviter.M().CreateInvite(false);
  TEST(invite && !invite->m_link.empty(), ());
  auto opened = joiner.M().OpenInvite(invite->m_link);
  TEST(opened, ());
  if (opened->m_stage == PairingInfo::Stage::NeedsConsent)
  {
    for (auto const & url : opened->m_needsConsent)
      joiner.M().SetConsent(url, Consent::NotNow, "");
    opened = joiner.M().OpenInvite(invite->m_link);
  }
  TEST(opened && opened->m_stage == PairingInfo::Stage::Waiting, ());
  world.Run(3'000);
  PairingInfo const & atInviter = inviter.Events().m_pairings[invite->m_id];
  PairingInfo const & atJoiner = joiner.Events().m_pairings[opened->m_id];
  TEST(atInviter.m_stage == PairingInfo::Stage::CompareCode && atJoiner.m_stage == PairingInfo::Stage::CompareCode,
       (static_cast<int>(atInviter.m_stage), static_cast<int>(atJoiner.m_stage)));
  TEST(atInviter.m_sas == atJoiner.m_sas && !atInviter.m_sas.empty(), ("both screens show the same code"));
  joiner.M().ConfirmCode(opened->m_id, true);
  inviter.M().Decide(invite->m_id, true, true);
  world.Run(3'000);
  TEST(joiner.Events().m_pairings[opened->m_id].m_stage == PairingInfo::Stage::Connected, ());
}

UNIT_TEST(Manager_PairsEndToEnd)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.Contact("Bob") && bob.Contact("Alice"), ("each phone has the other as a contact"));
  TEST(alice.Contact("Bob")->m_verified && bob.Contact("Alice")->m_verified, ("both compared the codes"));
  world.Run(3'000);
  TEST(!alice.Contact("Bob")->m_waiting, ("Bob's confirmation reached Alice"));
  TEST(alice.Contact("Bob")->m_sas == bob.Contact("Alice")->m_sas, ());
}

UNIT_TEST(Manager_SharesWithLiveUpdates)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  alice.M().SetForeground(false);

  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  TEST(alice.Events().m_location == LocationRequest::Idle, ("idle until someone watches"));
  alice.M().OnLocation(FixAt(world, 52.52, 13.405));
  world.Run(2'000);
  PositionInfo const * seen = bob.Position("Alice");
  TEST(seen && std::abs(seen->m_location.m_lat - 52.52) < 1e-9, ("Bob sees Alice"));
  TEST(bob.Contact("Alice")->m_sharesWithMeUntil == std::optional<int64_t>(0), ());

  // Bob's app watches: Alice goes live, and each fix reaches Bob within a second.
  TEST(alice.Events().m_location == LocationRequest::Live, ("Bob's watch signal made Alice live"));
  world.Run(3'000);
  alice.M().OnLocation(FixAt(world, 52.5201, 13.405));
  int64_t const sent = world.m_executor.NowMs();
  while (bob.Position("Alice")->m_location.m_lat < 52.52005 && world.m_executor.NowMs() < sent + 10'000)
    world.Run(50);
  TEST_LESS(world.m_executor.NowMs() - sent, 1000, ("a live fix arrives within a second"));

  // Bob closes the map: after the lease, Alice is idle again.
  bob.M().SetForeground(false);
  world.Run(130'000);
  TEST(alice.Events().m_location == LocationRequest::Idle, ("the lease ran out"));
}

UNIT_TEST(Manager_WorksWithTwoOfThreeRelaysDown)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  world.Relay("wss://nos.lol").SetDown(true);
  world.Relay("wss://nostr.mom").SetDown(true);
  world.Run(1'000);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 48.85, 2.35));
  world.Run(20'000);
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 48.85) < 1e-9,
       ("shared through the one relay left"));
}

UNIT_TEST(Manager_OneDishonestRelayCannotHideWhatTheOthersDeliver)
{
  World world;
  // nos.lol sends every event with a broken signature, ahead of the other two.
  world.Relay("wss://nos.lol").m_forge = true;
  world.Relay("wss://nos.lol").m_latencyMs = 5;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.Contact("Bob") && bob.Contact("Alice"), ("paired"));
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 48.85, 2.35));
  world.Run(5'000);
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 48.85) < 1e-9,
       ("the share reaches Bob through the honest relays"));
}

void SetDown(World & world, std::vector<std::string_view> const & urls, bool down)
{
  for (auto const & url : urls)
    world.Relay(std::string(url)).SetDown(down);
}

std::vector<std::string_view> const kDefaults(kDefaultRelays.begin(), kDefaultRelays.end());

size_t EventsReceived(World & world, std::string const & url)
{
  size_t n = 0;
  for (auto const & [link, messages] : world.Relay(url).m_received)
    for (auto const & message : messages)
      n += message.rfind("[\"EVENT\"", 0) == 0 ? 1 : 0;
  return n;
}

UNIT_TEST(Manager_ChangedHomeRelaysReachContacts)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Phone carol(world, "Carol");
  Pair(world, alice, bob);
  Pair(world, alice, carol);
  carol.M().SetForeground(false);  // Carol does not open CoMaps for a few days

  // Alice moves to a relay of her own (D5). Bob's app is open: it learns the new list at once, and asks
  // before sending there.
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  world.Run(3'000);
  TEST(alice.Contact("Bob")->m_notMoved, ("Bob may not send to Alice's relay yet"));
  TEST_EQUAL(bob.Events().m_consents.size(), 1, ());
  TEST_EQUAL(bob.Events().m_consents[0].m_url, kOwn, ());
  TEST(bob.Events().m_consents[0].m_purpose == ConsentRequest::Purpose::Sending, ());
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  world.Run(3'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ("allowed: Bob answers there"));
  SetDown(world, kDefaults, true);
  TEST(bob.M().StartSharing({{bob.Id("Alice"), 0}}), ());
  world.Run(20'000);
  TEST(alice.Contact("Bob")->m_sharesWithMeUntil, ("Bob's grant came through the new relay alone"));
  SetDown(world, kDefaults, false);
  bob.M().StopSharing();
  world.Run(20'000);

  // Two days later, nobody having opened CoMaps since, Carol shares: she still sends to the old
  // relays, which Alice still reads.
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(2 * 86'400'000);
  carol.M().SetForeground(true);
  alice.M().SetForeground(true);
  TEST(carol.M().StartSharing({{carol.Id("Alice"), 0}}), ());
  world.Run(5'000);
  TEST(alice.Contact("Carol")->m_sharesWithMeUntil, ("through the old relays, still read that week"));

  // Alice's app, open again that week, has sent Carol the new list too.
  carol.M().SetConsent(kOwn, Consent::Allow, "Alice");
  SetDown(world, kDefaults, true);
  int64_t const until = world.m_executor.Now() + 3600;
  TEST(carol.M().ExtendSharing(carol.Id("Alice"), until), ());
  world.Run(20'000);
  TEST(alice.Contact("Carol")->m_sharesWithMeUntil == std::optional<int64_t>(until), ("Carol learned the new relay"));
  SetDown(world, kDefaults, false);
  carol.M().StopSharing();
  world.Run(20'000);

  // After the week, the old relays are no longer read.
  alice.M().SetForeground(false);
  carol.M().SetForeground(false);
  world.Run(7 * 86'400'000);
  alice.M().SetForeground(true);
  world.Run(120'000);
  auto const connections = alice.M().Pool().Connections();
  TEST(!connections.empty(), ());
  for (auto const & connection : connections)
    TEST_EQUAL(connection.first, kOwn, ());
}

UNIT_TEST(Manager_RelaysAndNamesFitTheMessagesTheyGoIn)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  world.Run(3'000);

  // A URL of the longest length that ends in n times c. Quotes and backslashes take two bytes each in
  // JSON: four URLs of them would not fit a state.
  auto const url = [](char c, size_t n)
  { return "wss://" + std::string(kMaxRelayUrl - 6 - n, 'a') + std::string(n, c); };
  TEST(!alice.M().SetHomeRelays({url('"', 1)}) && !alice.M().SetHomeRelays({url('\\', 1)}), ());
  TEST(!alice.M().SetHomeRelays({url('"', 58), url('\\', 58), url('"', 57), url('\\', 57)}), ());

  // The longest relay lists that are valid do, with the longest dot colour.
  TEST(alice.M().SetColor("deeppurple"), ());
  TEST(alice.M().SetHomeRelays({url('1', 1), url('2', 1), url('3', 1), url('4', 1)}), ());
  world.Run(3'000);
  TEST_EQUAL(alice.M().GetSettings().m_homeRelays.size(), 4, ());

  // Names: control characters take six bytes each in JSON, and have no place in a name.
  TEST(!alice.M().SetName(std::string(kMaxName, '\x01')) && !alice.M().SetName("Al\tice"), ());
  TEST(alice.M().SetName(std::string(kMaxName, '"')), ());
}

UNIT_TEST(Manager_ChangingHomeRelaysMovesARunningShare)
{
  World world;
  std::string const kOwn = "wss://own.example";
  std::string const kBobs = "wss://bob.example";
  world.m_transport.Add(kOwn);
  world.m_transport.Add(kBobs);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  TEST(bob.M().SetHomeRelays({kBobs}), ());
  alice.M().SetConsent(kBobs, Consent::Allow, "Bob");
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  Pair(world, alice, bob);

  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 52.52, 13.405));
  world.Run(3'000);
  TEST(bob.Position("Alice"), ());
  TEST(alice.Events().m_location == LocationRequest::Live, ("Bob watches"));

  // Alice moves to her own relay, and her old relays go down: the share carries on there.
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  SetDown(world, kDefaults, true);
  world.Run(125'000);  // the new stream's first 30..120 s are silent (spec §9)
  alice.M().OnLocation(FixAt(world, 52.53, 13.405));
  world.Run(5'000);
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 52.53) < 1e-9,
       ("Bob follows the new stream on the new relay"));
  world.Run(130'000);
  TEST(alice.Events().m_location == LocationRequest::Live, ("Bob's signals reach the new listening relay"));
}

UNIT_TEST(Manager_AStoreOfAnotherVersionCannotBeRead)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);

  // Neither an earlier version's store, of a development build, nor a later one's is read: like any store
  // that cannot be read, the app offers to delete it.
  store::Store store(alice.Path(), alice.Keys(), ScenarioRng());
  SecretBytes contents;
  TEST(store.Load(contents) == store::Store::Result::Loaded, ());
  for (int const step : {-1, 1})
  {
    SecretBytes other(ByteSpan(contents.data(), contents.size()));
    other[0] = static_cast<uint8_t>(contents[0] + step);
    TEST(store.Save(other, {}), ());
    TEST(!alice.Restart(false /* expectReadable */), ());
  }
  TEST_EQUAL(alice.Events().m_storeErrors, 2, ());
  alice.M().DeleteAllData();
  TEST(alice.M().SetName("Alice") && alice.M().CreateInvite(false), ("a fresh start"));
}

UNIT_TEST(Manager_AnOwnColourThisBuildDoesNotKnowIsAutomatic)
{
  // A palette changed during development leaves a colour name this build does not know. It reads as
  // automatic, as a contact's colour would, and costs nothing else: the contacts stay.
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.M().SetColor("teal"), ());
  store::Store store(alice.Path(), alice.Keys(), ScenarioRng());
  SecretBytes contents;
  TEST(store.Load(contents) == store::Store::Result::Loaded, ());
  std::string_view const teal = "teal";
  auto const colour = std::search(contents.begin(), contents.end(), teal.begin(), teal.end());
  TEST(colour != contents.end(), ());
  contents[colour - contents.begin() + 3] = 'k';  // "teak"
  TEST(store.Save(contents, {}), ());
  TEST(alice.Restart(), ());
  TEST(alice.M().GetSettings().m_color.empty() && alice.Contact("Bob"), ());
  TEST_EQUAL(alice.Events().m_storeErrors, 0, ());
}

UNIT_TEST(Manager_OldRelaysAreReadUntilEveryContactMovedForAtMost30Days)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Phone carol(world, "Carol");
  Phone dave(world, "Dave");
  Pair(world, alice, bob);
  Pair(world, alice, carol);
  Pair(world, alice, dave);
  bob.M().SetForeground(false);
  carol.M().SetForeground(false);
  dave.M().SetForeground(false);
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  carol.M().SetConsent(kOwn, Consent::Allow, "Alice");
  dave.M().SetConsent(kOwn, Consent::Refuse, "Alice");  // Dave refused Alice's relay ("Don't allow")

  TEST(alice.M().SetHomeRelays({kOwn}), ());
  world.Run(3'000);
  TEST(alice.Contact("Bob")->m_notMoved && alice.Contact("Carol")->m_notMoved, ("nobody has moved yet"));
  TEST(!alice.Contact("Bob")->m_moveOverdue, ());

  // Ten days later, past the old week, Bob opens CoMaps and shares: his grant still goes to the old
  // relays, which Alice still reads.
  alice.M().SetForeground(false);
  world.Run(10 * 86'400'000LL);
  alice.M().SetForeground(true);
  bob.M().SetForeground(true);
  TEST(bob.M().StartSharing({{bob.Id("Alice"), 0}}), ());
  world.Run(5'000);
  TEST(alice.Contact("Bob")->m_sharesWithMeUntil, ("through the old relays, still read"));
  // Opening the app, Alice sent each contact that has not moved her current state, naming her relay. Bob's
  // app answers there.
  TEST(!alice.Contact("Bob")->m_notMoved, ("Bob's answer came through the new relay"));
  TEST(alice.Contact("Carol")->m_notMoved, ());
  bob.M().StopSharing();
  world.Run(20'000);

  // Dave shares too: it arrives through the old relays, but Dave, who refused Alice's relay, cannot
  // answer, and shows as not moved.
  dave.M().SetForeground(true);
  TEST(dave.M().StartSharing({{dave.Id("Alice"), 0}}), ());
  world.Run(5'000);
  TEST(alice.Contact("Dave")->m_sharesWithMeUntil, ());
  TEST(alice.Contact("Dave")->m_notMoved, ("what came through the old relays tells nothing of a move"));
  dave.M().StopSharing();
  world.Run(20'000);
  dave.M().SetForeground(false);

  // After 30 days Carol, who never opened CoMaps, is overdue: the old relays are no longer read.
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(21 * 86'400'000LL);
  alice.M().SetForeground(true);
  world.Run(120'000);
  TEST(alice.Contact("Carol")->m_notMoved && alice.Contact("Carol")->m_moveOverdue, ());
  for (auto const & connection : alice.M().Pool().Connections())
    TEST_EQUAL(connection.first, kOwn, ());

  // Whenever Carol does open it, she hears of the move from Alice's state of that day, and answers.
  carol.M().SetForeground(true);
  world.Run(5'000);
  TEST(!alice.Contact("Carol")->m_notMoved && !alice.Contact("Carol")->m_moveOverdue, ());
}

UNIT_TEST(Manager_AContactAnswersAMoveOnce)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  world.Run(5'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ());

  // After the week of confirmations, Alice shares with Bob and stops, while Bob's app is closed.
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(8 * 86'400'000LL);
  alice.M().SetForeground(true);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 52.52, 13.405));
  world.Run(5'000);
  alice.M().StopSharing();
  world.Run(20'000);
  alice.M().SetForeground(false);
  world.Run(70'000);

  // Bob reads her states, which name the relays his answer already reached: nothing goes to them.
  size_t const before = EventsReceived(world, kOwn);
  bob.M().SetForeground(true);
  world.Run(10'000);
  TEST_EQUAL(EventsReceived(world, kOwn), before, ());
}

UNIT_TEST(Manager_AnAnswerDoesNotAskForTheOtherRelays)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);

  // Alice puts a relay of her own first. Bob's app answers through the default relay she kept, and asks
  // nothing: the answer does not need her relay.
  TEST(alice.M().SetHomeRelays({kOwn, std::string(kDefaults[0])}), ());
  world.Run(5'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ());
  TEST(bob.Events().m_consents.empty(), ());

  // So when she shares, the one question about her relay says what it is for. Each relay is asked about
  // once: a question as the answer left would have taken its place.
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 52.52, 13.405));
  world.Run(5'000);
  TEST_EQUAL(bob.Events().m_consents.size(), 1, ());
  TEST_EQUAL(bob.Events().m_consents[0].m_url, kOwn, ());
  TEST(bob.Events().m_consents[0].m_purpose == ConsentRequest::Purpose::LiveUpdates, ());
}

UNIT_TEST(Manager_NobodyWaitsForAContactThatNeverFinishedConnecting)
{
  World world;
  std::string const kOwn = "wss://own.example";
  std::string const kCarols = "wss://carol.example";
  world.m_transport.Add(kOwn);
  world.m_transport.Add(kCarols);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  alice.M().SetConsent(kCarols, Consent::Allow, "Carol");
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");

  // Carol, on a relay of her own, opens Alice's invite and compares the codes, then loses her phone before
  // Alice accepts: Alice's contact for her never finishes connecting.
  std::string inviteId;
  {
    Phone carol(world, "Carol");
    TEST(carol.M().SetHomeRelays({kCarols}), ());
    carol.M().SetForeground(true);
    auto const invite = alice.M().CreateInvite(false);
    auto const opened = carol.M().OpenInvite(invite->m_link);
    TEST(opened && opened->m_stage == PairingInfo::Stage::Waiting, ());
    world.Run(3'000);
    carol.M().ConfirmCode(opened->m_id, true);
    inviteId = invite->m_id;
  }
  alice.M().Decide(inviteId, true, true);
  world.Run(3'000);
  TEST(alice.Contact("Carol") && alice.Contact("Carol")->m_waiting, ());
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(8 * 86'400'000LL);
  alice.M().SetForeground(true);
  bob.M().SetForeground(true);
  world.Run(3'000);
  TEST(alice.Contact("Carol")->m_offerRemoval, ("past her first week"));

  // Alice moves to a relay of her own, and Bob answers. Carol, who will not, is not labelled as not moved
  // (she is offered for removal instead), the old relays are not read for her, and she gets the new list
  // once, not again each day.
  size_t const toCarol = EventsReceived(world, kCarols);
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  world.Run(5'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ());
  TEST(!alice.Contact("Carol")->m_notMoved && alice.Contact("Carol")->m_offerRemoval, ());
  world.Run(120'000);
  auto const connections = alice.M().Pool().Connections();
  TEST(!connections.empty(), ());
  for (auto const & connection : connections)
    TEST_EQUAL(connection.first, kOwn, ());
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  for (int day = 1; day <= 2; ++day)
  {
    world.Run(86'400'000);
    alice.M().SetForeground(true);
    world.Run(10'000);
    alice.M().SetForeground(false);
  }
  TEST_EQUAL(EventsReceived(world, kCarols), toCarol + 1, ());
}

UNIT_TEST(Manager_TimeLimitsAndStop)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  int64_t const until = world.m_executor.Now() + 600;
  TEST(alice.M().StartSharing({{alice.Id("Bob"), until}}), ());
  alice.M().OnLocation(FixAt(world, 41.9, 12.5));
  world.Run(2'000);
  TEST(bob.Position("Alice") && bob.Contact("Alice")->m_sharesWithMeUntil == std::optional<int64_t>(until), ());
  world.Run((until - world.m_executor.Now()) * 1000 + 15'000);
  TEST(!alice.Events().m_sharing.m_active && alice.Events().m_location == LocationRequest::Off,
       ("the share ended on time on Alice's side"));
  TEST(!bob.Contact("Alice")->m_sharesWithMeUntil, ("and on Bob's"));
  world.Run(130'000);
  TEST(!bob.Position("Alice"), ("the position is gone"));

  // Stop: the position goes stale, then disappears with the state without a grant.
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 41.9, 12.5));
  world.Run(2'000);
  TEST(bob.Position("Alice"), ());
  alice.M().StopSharing();
  world.Run(15'000);
  TEST(!bob.Position("Alice") && !bob.Contact("Alice")->m_sharesWithMeUntil, ("stopping ends it for Bob"));
}

UNIT_TEST(Manager_AContactShownAgainIsFollowedAtOnce)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  std::string const aliceId = bob.Id("Alice");
  alice.M().SetForeground(false);

  // Hidden while Alice shares: no dot, and nobody watches her, so her share goes idle.
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 41.9, 12.5));
  world.Run(2'000);
  TEST(bob.Position("Alice") && alice.Events().m_location == LocationRequest::Live, ());
  bob.M().SetHidden(aliceId, true);
  world.Run(130'000);
  TEST(!bob.Position("Alice") && alice.Events().m_location == LocationRequest::Idle, ("a hidden contact has no dot"));
  alice.M().OnLocation(FixAt(world, 41.95, 12.5));
  world.Run(2'000);
  TEST(!bob.Position("Alice"), ());

  // Shown again: her share is followed at once, without a new state from her, and watched again.
  bob.M().SetHidden(aliceId, false);
  world.Run(2'000);
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 41.95) < 1e-9,
       ("Bob follows Alice again"));
  TEST(alice.Events().m_location == LocationRequest::Live, ("Bob's watch signal"));

  // Hidden before a share starts: the share is known meanwhile, though neither shown nor watched, and
  // followed once she is shown.
  alice.M().StopSharing();
  world.Run(15'000);
  bob.M().SetHidden(aliceId, true);
  world.Run(130'000);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 42.0, 12.5));
  world.Run(5'000);
  TEST(!bob.Position("Alice") && bob.Contact("Alice")->m_sharesWithMeUntil, ("known, not shown"));
  TEST(alice.Events().m_location == LocationRequest::Idle, ("nobody watches a hidden contact"));
  bob.M().SetHidden(aliceId, false);
  world.Run(2'000);
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 42.0) < 1e-9, ());

  // A share whose end never reached Bob while she was hidden is not followed once she is shown: its time
  // limit is enforced locally, as while viewing.
  alice.M().StopSharing();
  world.Run(15'000);
  bob.M().SetHidden(aliceId, true);
  int64_t const until = world.m_executor.Now() + 60;
  TEST(alice.M().StartSharing({{alice.Id("Bob"), until}}), ());
  world.Run(5'000);
  TEST(bob.Contact("Alice")->m_sharesWithMeUntil == std::optional<int64_t>(until), ());
  for (auto const url : kDefaults)
    world.Relay(std::string(url)).m_deaf = true;  // her end does not reach Bob
  world.Run(70'000);
  bob.M().SetHidden(aliceId, false);
  TEST(!bob.Contact("Alice")->m_sharesWithMeUntil, ("the share ended meanwhile"));
}

UNIT_TEST(Manager_OnlyWhatHasNotEndedResumes)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Phone carol(world, "Carol");
  Pair(world, alice, bob);
  Pair(world, alice, carol);

  // Alice's process dies while she shares with Bob for ten minutes and with Carol until she stops.
  int64_t const until = world.m_executor.Now() + 600;
  TEST(alice.M().StartSharing({{alice.Id("Bob"), until}, {alice.Id("Carol"), 0}}), ());
  world.Run(2'000);
  alice.Restart();
  TEST_EQUAL(alice.Events().m_sharing.m_resumable.size(), 2, ());

  // Opened after Bob's end, the app offers to resume the share with Carol only.
  world.Run(600'000);
  alice.Restart();
  auto const resumable = alice.Events().m_sharing.m_resumable;
  TEST(resumable.size() == 1 && resumable[0].first == alice.Id("Carol"), ());
  TEST(alice.M().StartSharing(resumable), ());
}

UNIT_TEST(Manager_RemovingSomeoneKeepsTheOthers)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Phone carol(world, "Carol");
  Pair(world, alice, bob);
  Pair(world, alice, carol);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}, {alice.Id("Carol"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 40.4, -3.7));
  world.Run(2'000);
  TEST(bob.Position("Alice") && carol.Position("Alice"), ());
  TEST(alice.M().ChangeSharing({{alice.Id("Bob"), 0}}), ());
  world.Run(130'000);
  alice.M().OnLocation(FixAt(world, 40.41, -3.7));
  world.Run(5'000);
  TEST(!carol.Position("Alice") && !carol.Contact("Alice")->m_sharesWithMeUntil, ("Carol is out"));
  TEST(bob.Position("Alice") && std::abs(bob.Position("Alice")->m_location.m_lat - 40.41) < 1e-9,
       ("Bob follows the new stream"));
}

UNIT_TEST(Manager_NoTrafficWhenUnused)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(61'000);
  TEST(alice.M().Pool().Connections().empty() && bob.M().Pool().Connections().empty(), ("everything closed"));
  auto const attempts = world.m_transport.m_attempts;
  world.Run(3'600'000);
  TEST(world.m_transport.m_attempts == attempts, ("no connection in an hour of not sharing in the background"));
}

UNIT_TEST(Manager_IdleSharingHoldsOneConnection)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetForeground(false);
  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 35.68, 139.69));
  int64_t const published = world.m_executor.NowMs();
  world.Run(70'000);
  auto const connections = alice.M().Pool().Connections();
  TEST(connections.size() == 1 && connections[0].first == "wss://nos.lol",
       ("one connection, to the listening relay", connections));
  world.m_executor.RunUntil(published + 300'000 + 2'000);
  TEST_EQUAL(alice.M().Pool().Connections().size(), 3, ("the heartbeat, 5 min on, publishes to every home relay"));
  world.Run(70'000);
  TEST_EQUAL(alice.M().Pool().Connections().size(), 1, ("and those connections close again"));

  // Bob opens the map: his watch signal reaches the listening relay, and Alice goes live.
  bob.M().SetForeground(true);
  world.Run(3'000);
  TEST(alice.Events().m_location == LocationRequest::Live, ());
}

UNIT_TEST(Manager_IdleSharingPublishesMovesNotJitter)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetForeground(false);
  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  double constexpr kMetre = 1.0 / 111'195;  // in degrees of latitude
  auto const fix = [&](double northM, double accuracyM)
  {
    Location f = FixAt(world, 48.8566 + northM * kMetre, 2.3522);
    f.m_acc = accuracyM;
    return f;
  };
  alice.M().OnLocation(fix(0, 30));
  world.Run(31'000);
  size_t const base = EventsReceived(world, "wss://nos.lol");
  TEST_GREATER(base, 0, ());

  // Balanced accuracy, lying still: fixes 55 m apart, each +-30 m. Their circles overlap: nothing.
  for (int i = 0; i < 8; ++i)
  {
    alice.M().OnLocation(fix(i % 2 == 0 ? 55 : 0, 30));
    world.Run(31'000);
  }
  TEST_EQUAL(EventsReceived(world, "wss://nos.lol"), base, ("jitter is not a move"));

  // A fix three times as accurate goes out, then each 25 m step of a walk with good fixes.
  alice.M().OnLocation(fix(0, 10));
  world.Run(31'000);
  TEST_EQUAL(EventsReceived(world, "wss://nos.lol"), base + 1, ("sharper"));
  for (int i = 1; i <= 3; ++i)
  {
    alice.M().OnLocation(fix(25 * i, 8));
    world.Run(31'000);
  }
  TEST_EQUAL(EventsReceived(world, "wss://nos.lol"), base + 4, ("a walk"));

  // Lying still with GPS: jumps of 16 m stay below 20 m.
  for (int i = 0; i < 4; ++i)
  {
    alice.M().OnLocation(fix(75 + (i % 2 == 0 ? 16 : 0), 5));
    world.Run(31'000);
  }
  TEST_EQUAL(EventsReceived(world, "wss://nos.lol"), base + 4, ());
}

UNIT_TEST(Manager_AListeningRelayThatStopsDeliveringIsLeft)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetForeground(false);
  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 35.68, 139.69));
  world.Run(200'000);  // the new stream's silence, its first event, and the publishing connections closing
  auto connections = alice.M().Pool().Connections();
  TEST(connections.size() == 1 && connections[0].first == "wss://nos.lol", (connections));

  // nos.lol still accepts events, but delivers none: Bob's signals would never reach Alice there. The
  // next event Alice publishes does not come back, and she listens on the next relay.
  world.Relay("wss://nos.lol").m_deaf = true;
  alice.M().OnLocation(FixAt(world, 35.681, 139.69));
  world.Run(20'000);
  TEST(alice.M().Pool().IsDeaf("wss://nos.lol"), ());
  world.Run(70'000);
  connections = alice.M().Pool().Connections();
  TEST(connections.size() == 1 && connections[0].first == "wss://nostr.mom", (connections));

  bob.M().SetForeground(true);
  world.Run(3'000);
  TEST(alice.Events().m_location == LocationRequest::Live, ("Bob's signal arrives through nostr.mom"));
}

UNIT_TEST(Manager_TheDefaultRelaysAreJudgedFromTheStart)
{
  // A fresh install whose listening relay, nos.lol, is deaf already: it has never sent anything back, but
  // as a default relay it is judged, and the second post moves the inbox (the first leaves before the
  // listening subscription is open).
  World world;
  world.Relay("wss://nos.lol").m_deaf = true;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetForeground(false);
  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  for (int i = 0; i < 2; ++i)
  {
    alice.M().OnLocation(FixAt(world, 35.68 + i * 0.001, 139.69));
    world.Run(100'000);
  }
  auto const connections = alice.M().Pool().Connections();
  TEST(connections.size() == 1 && connections[0].first == "wss://nostr.mom", (connections));
}

UNIT_TEST(Manager_ARelayThatEverSentAnEventBackIsJudgedInEveryRun)
{
  // Alice listens on a relay of her own, which unlike the default relays is judged only once it has sent
  // something back.
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  Relays const withOwn = {kOwn, "wss://nostr.mom", "wss://relay.nostr.net"};
  Relays const withoutOwn = {"wss://nostr.mom", "wss://relay.nostr.net"};
  TEST(alice.M().SetHomeRelays(withOwn), ());
  world.Run(10'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ());
  bob.M().SetForeground(false);
  alice.M().SetForeground(false);
  double lat = 35.68;
  // Starts a share, and gives the relay it listens on once things settle.
  auto const share = [&]
  {
    TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
    // The first event leaves before the listening subscription is open, so nothing waits for it to come
    // back: the second one tells.
    for (int i = 0; i < 2; ++i)
    {
      lat += 0.001;
      alice.M().OnLocation(FixAt(world, lat, 139.69));
      world.Run(100'000);  // the echo or the wait for it, and the publishing connections closing
    }
    auto const connections = alice.M().Pool().Connections();
    return connections.size() == 1 ? connections[0].first : std::string();
  };
  auto const stop = [&]
  {
    alice.M().StopSharing();
    world.Run(20'000);
  };

  // Her relay, the listening relay, sends Alice's events back. Then her CoMaps is killed, and the relay
  // stops delivering.
  TEST_EQUAL(share(), kOwn, ());
  alice.Restart();
  alice.M().DismissResume();
  world.Relay(kOwn).m_deaf = true;

  // In the next run, the first event that should come back does not, and Alice listens on the next relay;
  // still so weeks later.
  TEST_EQUAL(share(), "wss://nostr.mom", ());
  stop();
  world.Run(40 * 86'400'000LL);
  alice.Restart();
  TEST_EQUAL(share(), "wss://nostr.mom", ());
  stop();

  // Only relays in use are remembered: once Alice has left hers, and nobody sends there any more, it is
  // forgotten. Coming back to it, she relies on it as on any relay that never sent anything back.
  alice.M().SetForeground(true);
  bob.M().SetForeground(true);
  TEST(alice.M().SetHomeRelays(withoutOwn), ());
  world.Run(10'000);
  TEST(!alice.Contact("Bob")->m_notMoved, ());
  TEST(alice.M().SetHomeRelays({withoutOwn.rbegin(), withoutOwn.rend()}), ());
  world.Run(10'000);
  TEST(alice.M().GetSettings().m_previousRelays.empty(), ());
  alice.Restart();
  TEST(alice.M().SetHomeRelays(withOwn), ());
  alice.M().SetForeground(false);
  bob.M().SetForeground(false);
  world.Run(10'000);
  TEST_EQUAL(share(), kOwn, ());
}

UNIT_TEST(Manager_LiveUpdatesNeedTheListeningRelay)
{
  World world;
  world.m_transport.Add("wss://relay.alice.example");
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  TEST(alice.M().SetHomeRelays({"wss://relay.alice.example", "wss://nos.lol"}), ());
  {
    // Bob is asked about Alice's own relay before pairing through it, and says "Not now": the pairing
    // goes through her other relay.
    alice.M().SetForeground(true);
    bob.M().SetForeground(true);
    auto const invite = alice.M().CreateInvite(false);
    auto const asked = bob.M().OpenInvite(invite->m_link);
    TEST(asked && asked->m_stage == PairingInfo::Stage::NeedsConsent &&
             asked->m_needsConsent == std::vector<std::string>{"wss://relay.alice.example"},
         ());
  }
  Pair(world, alice, bob);
  alice.M().SetForeground(false);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 59.33, 18.07));
  world.Run(70'000);
  TEST(bob.Position("Alice"), ("Bob still sees Alice through her other relay"));
  TEST(bob.Contact("Alice")->m_liveUpdatesOff, ("but without live updates, and says so"));
  TEST_EQUAL(bob.Contact("Alice")->m_liveRelay, "wss://relay.alice.example", ("the relay Bob may allow"));
  TEST(alice.Events().m_location == LocationRequest::Idle, ("Alice never heard Bob's signals"));
  bob.M().SetHidden(bob.Id("Alice"), true);
  TEST(!bob.Contact("Alice")->m_liveUpdatesOff, ("not while hidden: Bob does not view her"));
  bob.M().SetHidden(bob.Id("Alice"), false);
  TEST(bob.Contact("Alice")->m_liveUpdatesOff, ());

  bob.M().SetConsent(bob.Contact("Alice")->m_liveRelay, Consent::Allow, "Alice");
  world.Run(70'000);
  TEST(!bob.Contact("Alice")->m_liveUpdatesOff && alice.Events().m_location == LocationRequest::Live,
       ("allowed: live updates start"));
  TEST(bob.Contact("Alice")->m_liveRelay.empty(), ());
}

UNIT_TEST(Manager_AnInviteThroughRelaysNotAllowedNamesThem)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  auto const invite = alice.M().CreateInvite(false);
  auto const cancelledFor = [](std::optional<PairingInfo> const & opened, std::string const & url)
  {
    return opened && opened->m_stage == PairingInfo::Stage::Cancelled && opened->m_id.empty() &&
           opened->m_needsConsent == std::vector<std::string>{url};
  };

  // Bob is asked about Alice's relay, and puts it off: the invite says which relay it would need, as it
  // does after a refusal. Allowed, it works.
  auto const asked = bob.M().OpenInvite(invite->m_link);
  TEST(asked && asked->m_stage == PairingInfo::Stage::NeedsConsent, ());
  bob.M().SetConsent(kOwn, Consent::NotNow, "");
  TEST(cancelledFor(bob.M().OpenInvite(invite->m_link), kOwn), ());
  bob.M().SetConsent(kOwn, Consent::Refuse, "");
  TEST(cancelledFor(bob.M().OpenInvite(invite->m_link), kOwn), ());
  bob.M().SetConsent(kOwn, Consent::Allow, "");
  auto const opened = bob.M().OpenInvite(invite->m_link);
  TEST(opened && opened->m_stage == PairingInfo::Stage::Waiting, ());
}

UNIT_TEST(Manager_NotNowAsksAgainInTheNextRunDontAllowNever)
{
  World world;
  std::string const kOwn = "wss://own.example";
  world.m_transport.Add(kOwn);
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  auto const & asked = bob.Events().m_consents;
  auto const shareAndStop = [&]
  {
    TEST(bob.M().StartSharing({{bob.Id("Alice"), 0}}), ());
    world.Run(3'000);
    bob.M().StopSharing();
    world.Run(20'000);
  };

  // Alice moves to a relay of her own. Bob's app asks before sending there, and he answers "Not now":
  // nothing can reach Alice, and her contact says which relay it would take.
  TEST(alice.M().SetHomeRelays({kOwn}), ());
  world.Run(3'000);
  TEST_EQUAL(asked.size(), 1, ());
  bob.M().SetConsent(kOwn, Consent::NotNow, "Alice");
  TEST_EQUAL(bob.Contact("Alice")->m_blockedRelay, kOwn, ());
  TEST(bob.M().GetSettings().m_declined.empty(), ());

  // Not asked again in this run, even for a share; asked again in the next.
  shareAndStop();
  TEST_EQUAL(asked.size(), 1, ());
  bob.Restart();
  bob.M().SetForeground(true);
  shareAndStop();
  TEST_EQUAL(asked.size(), 2, ());

  // "Don't allow" is kept: never asked again, and listed in Settings with the contact it was for.
  bob.M().SetConsent(kOwn, Consent::Refuse, "Alice");
  bob.Restart();
  bob.M().SetForeground(true);
  TEST(bob.M().StartSharing({{bob.Id("Alice"), 0}}), ());
  world.Run(3'000);
  TEST_EQUAL(asked.size(), 2, ());
  auto const & declined = bob.M().GetSettings().m_declined;
  TEST(declined.size() == 1 && declined.begin()->first == kOwn && declined.begin()->second == "Alice", ());
  TEST_EQUAL(bob.Contact("Alice")->m_blockedRelay, kOwn, ("the label is where it can be allowed"));
  TEST(!alice.Contact("Bob")->m_sharesWithMeUntil, ());

  // Allowed after all: Bob's app answers through it, with the share.
  bob.M().SetConsent(kOwn, Consent::Allow, "Alice");
  world.Run(5'000);
  TEST(bob.M().GetSettings().m_declined.empty() && bob.Contact("Alice")->m_blockedRelay.empty(), ());
  TEST(!alice.Contact("Bob")->m_notMoved && alice.Contact("Bob")->m_sharesWithMeUntil, ());
}

UNIT_TEST(Manager_SurvivesRestartsAndRotatesKeys)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");

  // A link pairing across restarts of both apps.
  alice.M().SetForeground(true);
  bob.M().SetForeground(true);
  auto const invite = alice.M().CreateInvite(true);
  alice.Restart();
  alice.M().SetForeground(true);
  auto const opened = bob.M().OpenInvite(invite->m_link);
  world.Run(3'000);
  bob.Restart();
  bob.M().SetForeground(true);
  world.Run(3'000);
  auto const & aliceView = alice.Events().m_pairings[invite->m_id];
  TEST(aliceView.m_stage == PairingInfo::Stage::CompareCode && aliceView.m_peerName == "Bob", ());
  std::string const aliasBefore = *alice.Keys().Aliases().begin();
  alice.M().Decide(invite->m_id, true, false);
  TEST(*alice.Keys().Aliases().begin() != aliasBefore && alice.Keys().Aliases().size() == 1,
       ("the pairing's secrets are erased: the store's keys rotated"));
  world.Run(3'000);
  TEST(bob.Contact("Alice") && !bob.Contact("Alice")->m_verified, ("connected without comparing: unverified"));

  // Restarted, Bob still follows Alice.
  bob.Restart();
  bob.M().SetForeground(true);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 60.17, 24.94));
  world.Run(3'000);
  TEST(bob.Position("Alice"), ("a restarted viewer reads its contacts' shares"));

  // Alice's process dies while sharing: she is offered to resume, nothing restarts by itself.
  alice.Restart();
  TEST(!alice.Events().m_sharing.m_active && alice.Events().m_sharing.m_resumable.size() == 1, ());
  alice.M().DismissResume();
  TEST(alice.Events().m_sharing.m_resumable.empty(), ());

  // At 01:00 UTC yesterday's chain keys go, and with them the store's keys.
  bob.M().SetForeground(false);
  std::string const alias = *bob.Keys().Aliases().begin();
  int64_t const oneAm = EpochEnd(EpochOf(world.m_executor.Now())) + kControlGrace;
  world.Run((oneAm - world.m_executor.Now()) * 1000 + 1'000);
  TEST(*bob.Keys().Aliases().begin() != alias, ("the ratchet rotated Bob's store keys"));
}

UNIT_TEST(Manager_DeletingAContactStopsSharingAndRotates)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 1, 2));
  world.Run(2'000);
  std::string const alias = *alice.Keys().Aliases().begin();
  alice.M().DeleteContact(alice.Id("Bob"));
  world.Run(15'000);
  TEST(!alice.Contact("Bob") && !alice.Events().m_sharing.m_active, ());
  TEST(*alice.Keys().Aliases().begin() != alias, ("the contact's keys are erased: rotated"));
  TEST(!bob.Contact("Alice")->m_sharesWithMeUntil, ("Bob was told the share ended"));
}

UNIT_TEST(Manager_DeletingUnreadableDataStartsAfresh)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);

  // The key store lost the wrapping key, e.g. after the app's data was restored to another phone.
  alice.Keys().DeleteAllExcept("");
  TEST(!alice.Restart(false /* expectReadable */), ());
  TEST_EQUAL(alice.Events().m_storeErrors, 1, ());
  TEST(!alice.M().CreateInvite(false), ("nothing works on a store that cannot be read"));

  alice.M().DeleteAllData();
  TEST(alice.Events().m_contacts.empty(), ());
  TEST(alice.M().SetName("Alice"), ());
  TEST(alice.M().CreateInvite(false), ("a fresh start"));
  alice.Restart();
  TEST_EQUAL(alice.Events().m_storeErrors, 1, ("the new store reads"));
}

UNIT_TEST(Manager_AStoreThatCannotBeReadIsNeverOverwritten)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);

  // The key store fails for a while: the store cannot be read at this start.
  alice.Keys().m_failing = true;
  TEST(!alice.Restart(false /* expectReadable */), ());
  TEST_EQUAL(alice.Events().m_storeErrors, 1, ());
  TEST(!alice.M().SetName("Alicia"), ("nothing is written over it"));
  TEST(!alice.M().SetHomeRelays({"wss://relay.example"}), ());
  alice.M().SetRequestLive(false);
  alice.M().SetConsent("wss://relay.example", Consent::Allow, "Bob");

  // It works again: everything is still there.
  alice.Keys().m_failing = false;
  alice.Restart();
  TEST(alice.Contact("Bob"), ("the contact survived"));
  TEST_EQUAL(alice.M().GetSettings().m_name, "Alice", ());
  TEST(alice.M().GetSettings().m_requestLive, ());
}

UNIT_TEST(Manager_AFailedWriteIsNoStoreError)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Phone carol(world, "Carol");
  Pair(world, alice, bob);
  Pair(world, alice, carol);

  // The key store fails while a deleted contact's keys need a new wrapping key: the write fails, but the
  // data was read and is the user's, and each change tries again. The app is told when writing starts to
  // fail, not at each failure.
  alice.Keys().m_failing = true;
  alice.M().DeleteContact(alice.Id("Bob"));
  world.Run(15'000);
  TEST(alice.M().SetName("Ally"), ());  // the erased keys still need a new wrapping key
  TEST_EQUAL(alice.Events().m_storeErrors, 0, ());
  TEST_EQUAL(alice.Events().m_writeFailures, 1, ());
  TEST(alice.M().IsStarted() && !alice.Contact("Bob"), ());

  // A write that works, then a failure again: told again.
  alice.Keys().m_failing = false;
  TEST(alice.M().SetName("Alicia"), ());
  alice.Keys().m_failing = true;
  alice.M().DeleteContact(alice.Id("Carol"));
  world.Run(15'000);
  TEST_EQUAL(alice.Events().m_writeFailures, 2, ());

  // The next change that works writes it all.
  alice.Keys().m_failing = false;
  TEST(alice.M().SetName("Alice"), ());
  alice.Restart();
  TEST(!alice.Contact("Bob") && !alice.Contact("Carol"), ());
  TEST_EQUAL(alice.M().GetSettings().m_name, "Alice", ());
  TEST_EQUAL(alice.Events().m_storeErrors, 0, ());
}

UNIT_TEST(Manager_StopWaitsForTheRelaysBeforeItIsFreed)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 1, 2));
  world.Run(2'000);
  TEST(bob.Position("Alice") && !alice.M().HasPendingPublications(), ());

  // The app turns the feature off: it frees the manager only once the stop has its answers.
  alice.M().StopSharing();
  TEST(alice.M().HasPendingPublications(), ("the states and the stream's end wait for their OKs"));
  int64_t const stopped = world.m_executor.NowMs();
  while (alice.M().HasPendingPublications() && world.m_executor.NowMs() < stopped + 30'000)
    world.Run(100);
  TEST(!alice.M().HasPendingPublications(), ());
  alice.Restart();
  world.Run(5'000);
  TEST(!bob.Contact("Alice")->m_sharesWithMeUntil, ("Bob was told the share ended"));
  TEST(!bob.Position("Alice") || bob.Position("Alice")->m_stale, ());
}

UNIT_TEST(Manager_SendsOnlyFixesReceiversAccept)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());

  // A fix without a usable position is dropped: nothing to publish. (Non-finite values from their bits:
  // this file is built with -ffast-math.)
  Location broken = FixAt(world, FromBits(0x7ff8000000000000), 13.4);
  alice.M().OnLocation(broken);
  broken = FixAt(world, 91, 13.4);
  alice.M().OnLocation(broken);
  world.Run(2'000);
  TEST(!bob.Position("Alice"), ("no position from broken fixes"));

  // A field out of range is left out; the rest goes through.
  Location fix = FixAt(world, 52.52, 13.405);
  fix.m_brg = 360;
  fix.m_spd = FromBits(0x7ff0000000000000);
  fix.m_alt = 34;
  alice.M().OnLocation(fix);
  world.Run(2'000);
  PositionInfo const * seen = bob.Position("Alice");
  TEST(seen && std::abs(seen->m_location.m_lat - 52.52) < 1e-9, ("Bob sees Alice"));
  TEST(seen && !seen->m_location.m_brg && !seen->m_location.m_spd && seen->m_location.m_alt == 34.0, ());
}

UNIT_TEST(Manager_TheDotColourTravelsWithTheShare)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  TEST(!alice.M().SetColor("grey") && !alice.M().SetColor("Teal"), ("the bookmark colours, without the greys"));
  TEST(alice.M().SetColor("teal"), ());
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnLocation(FixAt(world, 52.52, 13.405));
  world.Run(3'000);
  auto const shown = [&] { return MarksFor(bob.Events().m_positions); };
  TEST(bob.Position("Alice") && bob.Position("Alice")->m_color == "teal", ());
  TEST(shown().size() == 1 && shown()[0].m_rgba == DotColorRgba("teal"), ());

  // Changed while sharing, it reaches Bob at once. With none, Bob's app picks one.
  TEST(alice.M().SetColor("orange"), ());
  world.Run(3'000);
  TEST(shown().size() == 1 && shown()[0].m_rgba == DotColorRgba("orange"), ());
  TEST(alice.M().SetColor(""), ());
  world.Run(3'000);
  TEST(bob.Position("Alice")->m_color.empty(), ());
  TEST(shown().size() == 1 && shown()[0].m_rgba == ColorOf(bob.Id("Alice")), ());

  // Both phones keep it.
  TEST(alice.M().SetColor("purple"), ());
  world.Run(3'000);
  alice.Restart();
  bob.Restart();
  TEST_EQUAL(alice.M().GetSettings().m_color, "purple", ());
  TEST_EQUAL(bob.Contact("Alice")->m_color, "purple", ());
}

UNIT_TEST(Manager_LowBattery)
{
  World world;
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  Pair(world, alice, bob);
  auto const sharing = [&] { return alice.Events().m_sharing.m_active; };
  double lat = 52.52;
  auto const low = [&]
  {
    lat += 0.001;
    alice.M().OnLocation(FixAt(world, lat, 13.405));
    world.Run(4'000);  // live: fixes at least 3 s apart
    PositionInfo const * seen = bob.Position("Alice");
    TEST(seen && std::abs(seen->m_location.m_lat - lat) < 1e-9, ());
    return seen->m_location.m_low.value_or(false);
  };

  // At 15 % and below, Bob's app shows that Alice's battery is low; not while it charges.
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnBatteryLevel(16, false);
  TEST(!low(), ());
  alice.M().OnBatteryLevel(15, false);
  TEST(low(), ());
  alice.M().OnBatteryLevel(15, true);
  TEST(!low(), ());

  // The share stops when the battery runs down to 5 %, not while the phone charges, ...
  TEST_EQUAL(alice.M().GetSettings().m_lowBatteryStop, 5, ());
  alice.M().OnBatteryLevel(6, false);
  alice.M().OnBatteryLevel(4, true);
  TEST(sharing(), ());
  alice.M().OnBatteryLevel(5, false);
  TEST(!sharing(), ());
  world.Run(15'000);
  TEST(!bob.Contact("Alice")->m_sharesWithMeUntil, ());

  // ... but one started there runs: the user chose to share. Once the battery has been above, it stops;
  // charging up to the level is not above.
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnBatteryLevel(4, false);
  alice.M().OnBatteryLevel(5, true);
  alice.M().OnBatteryLevel(3, false);
  TEST(sharing(), ());
  alice.M().OnBatteryLevel(6, true);
  alice.M().OnBatteryLevel(5, false);
  TEST(!sharing(), ());

  // "Never" stops nothing; a level chosen while sharing applies at once, but not the same one again, and
  // not while the phone charges.
  TEST(!alice.M().SetLowBatteryStop(51) && !alice.M().SetLowBatteryStop(-1), ());
  TEST(alice.M().SetLowBatteryStop(0), ());
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnBatteryLevel(30, false);
  alice.M().OnBatteryLevel(1, false);
  TEST(sharing(), ());
  TEST(alice.M().SetLowBatteryStop(15), ());
  TEST(!sharing(), ());
  TEST(alice.M().StartSharing({{alice.Id("Bob"), 0}}), ());
  alice.M().OnBatteryLevel(1, false);
  TEST(alice.M().SetLowBatteryStop(15), ());
  TEST(sharing(), ());
  alice.M().OnBatteryLevel(1, true);
  TEST(alice.M().SetLowBatteryStop(20), ());
  TEST(sharing(), ());
  alice.Restart();
  TEST_EQUAL(alice.M().GetSettings().m_lowBatteryStop, 20, ());
}
}  // namespace manager_tests
