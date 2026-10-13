#include "testing/testing.hpp"

#include "live_location/live_location_tests/fake_relay.hpp"
#include "live_location/live_location_tests/scenario.hpp"

#include "live_location/manager/manager.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/store/store.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

// Whole phones against in-process relays: pairing, sharing, live updates, relays down, time limits,
// revocation, the connection policy, relay consent, restarts and the store's key rotation.
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

  std::vector<ContactInfo> m_contacts;
  std::map<std::string, PairingInfo> m_pairings;
  std::vector<PositionInfo> m_positions;
  size_t m_positionUpdates = 0;
  SharingInfo m_sharing;
  std::vector<ConsentRequest> m_consents;
  LocationRequest m_location = LocationRequest::Off;
  int m_storeErrors = 0;
};

class World;

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
  store::InsecureKeyWrapper & Keys() { return m_keys; }

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
  store::InsecureKeyWrapper m_keys;
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
      joiner.M().SetConsent(url, false, "");
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

UNIT_TEST(Manager_LiveUpdatesNeedTheListeningRelay)
{
  World world;
  world.m_transport.Add("wss://relay.alice.example");
  Phone alice(world, "Alice");
  Phone bob(world, "Bob");
  TEST(alice.M().SetHomeRelays({"wss://relay.alice.example", "wss://nos.lol"}), ());
  {
    // Bob is asked about Alice's own relay before pairing through it, and refuses: the pairing goes
    // through her other relay.
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

  bob.M().SetConsent(bob.Contact("Alice")->m_liveRelay, true, "Alice");
  world.Run(70'000);
  TEST(!bob.Contact("Alice")->m_liveUpdatesOff && alice.Events().m_location == LocationRequest::Live,
       ("allowed: live updates start"));
  TEST(bob.Contact("Alice")->m_liveRelay.empty(), ());
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
}  // namespace manager_tests
