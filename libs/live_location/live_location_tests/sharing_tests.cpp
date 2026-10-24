#include "testing/testing.hpp"

#include "live_location/live_location_tests/scenario.hpp"
#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/nip44.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/encoding/binary.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/persist.hpp"
#include "live_location/protocol/stream.hpp"

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

// The sharing scenarios of tools/python/live_location/test_protocol.py, ported: grants and locations,
// revocation, time limits, and the receiving rules of states and locations.
namespace sharing_tests
{
using namespace live_location;
using namespace live_location_tests;
using std::invalid_argument;  // TEST_THROW pastes its argument after "std::"

std::string Dump(Location const & location)
{
  return ToJson(location).Dump();
}

std::vector<std::string> MemberNames(json::Value const & object)
{
  std::vector<std::string> names;
  for (auto const & member : object.Members())
    names.push_back(member.first);
  std::sort(names.begin(), names.end());
  return names;
}

UNIT_TEST(Sharing_GrantsAndLocations)
{
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Paired const carol = Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0 + 100, false);
  ContactPtr const & aBob = bob.m_inviterSide;
  ContactPtr const & bobA = bob.m_joinerSide;
  ContactPtr const & carolA = carol.m_joinerSide;

  int64_t const now = kT0 + 200;
  Sharer alice(kRelaysA);
  Rekey const start = alice.Start({{aBob, now + 3600}, {carol.m_inviterSide, 0}}, rng, now);
  TEST(start.m_states.size() == 2 && !start.m_end &&
           std::all_of(start.m_states.begin(), start.m_states.end(),
                       [](auto const & state) { return state.second.m_kind == kKindStored; }),
       ("start: one state per recipient, no end"));
  Following bobView;
  Following carolView;
  Deliver(start.m_states, {{bobA, &bobView}, {carolA, &carolView}}, now + 1);
  Stream const stream = *alice.GetStream();
  TEST(bobView.Grant() && bobView.Grant()->m_until == now + 3600 && bobView.Grant()->m_pk == stream.Pubkey(),
       ("Bob reads his grant"));
  TEST(carolView.Grant() && carolView.Grant()->m_until == 0 && carolView.Grant()->m_pk == stream.Pubkey(),
       ("Carol reads hers"));
  std::string const towardsBob = aBob->m_outgoing.At(EpochOf(now)).Pubkey();
  auto const it = std::find_if(start.m_states.begin(), start.m_states.end(),
                               [&](auto const & state) { return state.second.m_pubkey == towardsBob; });
  TEST(it != start.m_states.end(), ());
  nostr::Event const grantBob = it->second;
  TEST(!ReadControl(*carolA, Wire(grantBob), now + 1), ("Carol cannot read Bob's grant"));
  TEST(!ReadControl(*bobA, Wire(grantBob), now + 2), ("a replayed grant is rejected (seq)"));

  Location const fix = Fix(now);
  auto const loc1 = alice.PublishLocation(fix, rng, now + 5);
  TEST(loc1, ("a new share publishes at once"));
  TEST_EQUAL(loc1->TagValue("expiration").value_or(""), std::to_string(loc1->m_createdAt + kTtlLocation),
             ("a location expires 900 s after it was made, whatever the recipients' time limits"));
  TEST_EQUAL(loc1->m_content.size(), 432, ("location content has a constant length"));
  TEST_EQUAL(grantBob.m_content.size(), 772, ("control content has a constant length"));
  TEST_EQUAL(StateEvent(*aBob, kRelaysA, std::nullopt, rng, now).m_content.size(), 772,
             ("a state without a grant is as long as one with"));
  auto const r1 = bobView.OnStream(Wire(*loc1), now + 6);
  TEST(r1 && std::holds_alternative<Location>(*r1) && SeqOf(*r1) == 1, ("Bob reads the location"));
  TEST(std::get<Location>(*r1).m_lat == 52.5200066 && bobView.Position() &&
           Dump(*bobView.Position()) == Dump(std::get<Location>(*r1)),
       ("the position is the one sent"));
  TEST(carolView.OnStream(Wire(*loc1), now + 6), ("Carol reads it too"));
  TEST(!bobView.OnStream(Wire(*loc1), now + 6), ("a replayed location is rejected (seq)"));

  // Tampering: flip a ciphertext byte, and sign again so that the envelope is valid. Discarded, not raised.
  Bytes raw = *Base64Decode(loc1->m_content);
  raw[40] ^= 1;
  nostr::Event const tampered =
      SignEvent(stream.m_secret, loc1->m_createdAt, loc1->m_kind, loc1->m_tags, Base64Encode(raw), rng);
  TEST(!ReadStream(*bobView.Grant(), tampered, 0, now + 6), ("tampered ciphertext is discarded silently"));
  // A recipient forging a location under its own key: the author must be the stream key.
  Stream forger = Stream::Create(rng);
  forger.m_key = stream.m_key;
  TEST(!ReadStream(*bobView.Grant(), forger.LocationEvent(fix, rng, now + 7), 0, now + 7),
       ("a recipient cannot forge the sharer's locations"));
  TEST(!ReadStream(*bobView.Grant(), *loc1, 0, now + 5 + kTtlLocation), ("an expired location is ignored"));

  // Adding someone goes through Change(): Extend() only moves a current recipient's time limit. A
  // newcomer added with Extend() would read the latest position, published before its grant.
  Paired const dave = Pair("Alice", kRelaysA, "Dave", kRelaysB, kT0, false);
  TEST_THROW(alice.Extend(dave.m_inviterSide, 0, rng, now + 8), invalid_argument, ("Extend() refuses a new recipient"));
  TEST_THROW(alice.Extend(aBob, now, rng, now + 8), invalid_argument, ("Extend() refuses a time limit in the past"));
  nostr::Event const extension = alice.Extend(aBob, now + 7200, rng, now + 8);
  auto const extended = ReadControl(*bobA, Wire(extension), now + 9);
  TEST(extended, ());
  bobView.OnState(*extended, now + 9);
  TEST(bobView.Grant()->m_until == now + 7200 && alice.GetStream()->Pubkey() == stream.Pubkey(),
       ("Extend(): same stream, later time limit"));
}

UNIT_TEST(Sharing_ARestartedViewerReadsTheLatestStateOnceMore)
{
  // What a state grants is kept in memory only, stream keys never being stored: after a restart the viewer
  // reads the latest state once more. An older one stays a replay, as does the latest one read again (§8).
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  ContactPtr const & bobA = bob.m_joinerSide;
  int64_t const now = kT0 + 200;
  Sharer alice(kRelaysA);
  Rekey const start = alice.Start({{bob.m_inviterSide, now + 3600}}, rng, now);
  TEST_EQUAL(start.m_states.size(), 1, ());
  nostr::Event const first = start.m_states[0].second;
  nostr::Event const extension = alice.Extend(bob.m_inviterSide, now + 7200, rng, now + 10);
  TEST(ReadControl(*bobA, Wire(first), now + 1) && ReadControl(*bobA, Wire(extension), now + 11), ());
  TEST(!ReadControl(*bobA, Wire(extension), now + 12), ("read again in the same run: a replay"));

  binary::Writer writer;
  persist::WriteContact(writer, *bobA);
  SecretBytes const saved = writer.Finish();
  binary::Reader reader(saved);
  ContactPtr const restarted = persist::ReadContact(reader);
  TEST(!ReadControl(*restarted, Wire(first), now + 20), ("an older state stays a replay"));
  auto const latest = ReadControl(*restarted, Wire(extension), now + 21);
  TEST(latest && latest->m_share && latest->m_share->m_until == now + 7200, ("the latest is read once more"));
  TEST(!ReadControl(*restarted, Wire(extension), now + 22), ("once"));
}

// --- Revocation: what a removed recipient sees must not depend on whether the share goes on ---

struct Revocation
{
  // What anyone watching the relays sees of each event: kind, content length, tag names, d, and
  // whether the old stream signed it.
  std::vector<std::tuple<int64_t, size_t, std::vector<std::string>, std::string, bool>> m_observed;
  // What Carol decrypts: ("state", member names) with her channel key, and ("end", member names) with
  // the old stream key, if she kept it.
  std::vector<std::pair<std::string, std::vector<std::string>>> m_carolReads;
  std::shared_ptr<Sharer> m_sharer;
  ContactPtr m_bobA;
  Following m_bob;
  Following m_carol;
  Key m_carolKey;
  Rekey m_rekey;
  int64_t m_t = 0;
};

/// Alice shares with Bob and Carol, then either removes Carol or stops sharing altogether.
Revocation Revoke(bool removeOnlyCarol)
{
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Paired const carol = Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0, false);
  ContactPtr const carolA = carol.m_joinerSide;
  Revocation r;
  r.m_bobA = bob.m_joinerSide;
  r.m_sharer = std::make_shared<Sharer>(kRelaysA);
  Sharer & sharer = *r.m_sharer;
  int64_t t = kT0 + 300;
  Deliver(sharer.Start({{bob.m_inviterSide, 0}, {carol.m_inviterSide, 0}}, rng, t).m_states,
          {{r.m_bobA, &r.m_bob}, {carolA, &r.m_carol}}, t);
  nostr::Event const first = Wire(*sharer.PublishLocation(Fix(t), rng, t + 1));
  r.m_bob.OnStream(first, t + 1);
  r.m_carol.OnStream(first, t + 1);
  std::string const oldPk = r.m_carol.Grant()->m_pk;
  r.m_carolKey = r.m_carol.Grant()->m_key;

  t += 60;
  r.m_rekey = removeOnlyCarol ? sharer.Change({{bob.m_inviterSide, 0}}, rng, t) : sharer.Stop(rng, t);
  std::vector<nostr::Event> published;
  for (auto const & state : r.m_rekey.m_states)
    published.push_back(state.second);
  published.push_back(*r.m_rekey.m_end);
  for (auto const & event : published)
  {
    std::vector<std::string> tagNames;
    for (auto const & tag : event.m_tags)
      tagNames.push_back(tag.at(0));
    r.m_observed.emplace_back(event.m_kind, event.m_content.size(), tagNames, event.TagValue("d").value_or("-"),
                              event.m_pubkey == oldPk);
  }
  for (auto const & event : published)
  {
    if (auto const state = ReadControl(*carolA, Wire(event), t))
    {
      auto const keys = IncomingKeys(*carolA, t);
      auto const body = OpenSealed(event.m_content, keys.at(event.m_pubkey).ConversationKey());
      r.m_carolReads.emplace_back("state", MemberNames(*body));
      r.m_carol.OnState(*state, t);
    }
    else if (event.m_pubkey == oldPk)
    {
      auto const body = OpenSealed(event.m_content, r.m_carolKey);
      r.m_carolReads.emplace_back("end", body ? MemberNames(*body) : std::vector<std::string>{"undecryptable"});
    }
  }
  r.m_t = t;
  return r;
}

UNIT_TEST(Sharing_RemovalLooksLikeStopping)
{
  auto & rng = ScenarioRng();
  Revocation removal = Revoke(true);
  Revocation stop = Revoke(false);
  TEST(removal.m_observed == stop.m_observed, ("relays see the same events for \"remove Carol\" and \"stop sharing\""));
  std::vector<std::pair<std::string, std::vector<std::string>>> const expected = {
      {"state", {"relays", "seq", "t", "ts"}}, {"end", {"seq", "t", "ts"}}};
  TEST(removal.m_carolReads == expected && stop.m_carolReads == expected,
       ("Carol decrypts the same in both cases: a state without a grant, and an end without a reason"));
  TEST(std::get<4>(removal.m_observed.back()) && std::none_of(removal.m_observed.begin(), removal.m_observed.end() - 1,
                                                              [](auto const & o) { return std::get<4>(o); }),
       ("states first, then the old stream's end"));
  TEST(!removal.m_carol.Grant() && !removal.m_carol.Position(), ("a removed viewer erases the key and the position"));

  Sharer & sharer = *removal.m_sharer;
  Following & bob = removal.m_bob;
  int64_t const t = removal.m_t;
  TEST(kRekeyDelayMin <= sharer.NotBefore() - t && sharer.NotBefore() - t <= kRekeyDelayMax,
       ("the new stream waits 30 to 120 s"));
  TEST(!sharer.PublishLocation(Fix(t), rng, sharer.NotBefore() - 1), ("the new stream is silent before that"));

  // States and the end travel over different relays: here the end reaches Bob first. He keeps the last
  // position, marked stale, switches to the new grant, and is current again with the new stream's first fix.
  std::string const position = Dump(*bob.Position());
  TEST(bob.OnStream(Wire(*removal.m_rekey.m_end), t) && !bob.Grant() && bob.Position() &&
           Dump(*bob.Position()) == position && bob.IsStale(),
       ("an end before the grant: Bob erases the stream key but keeps the position, stale"));
  Deliver(removal.m_rekey.m_states, {{removal.m_bobA, &bob}}, t + 1);
  TEST(bob.Grant() && bob.Grant()->m_pk == sharer.GetStream()->Pubkey() && Dump(*bob.Position()) == position &&
           bob.IsStale(),
       ("the grant arrives: Bob follows the new stream and still shows the stale position"));
  bob.Tick(t + kEndGrace + 60);
  TEST(bob.Position() && Dump(*bob.Position()) == position,
       ("with a current grant, the stale position stays until the new stream speaks"));
  nostr::Event const loc2 = Wire(*sharer.PublishLocation(Fix(t), rng, sharer.NotBefore()));
  TEST(bob.OnStream(loc2, sharer.NotBefore()) && !bob.IsStale(), ("Bob is current again with the new stream"));
  TEST(!OpenSealed(loc2.m_content, removal.m_carolKey), ("Carol cannot decrypt the new stream with the old key"));

  // Stop, with the end first: stale until the state without a grant, which removes the dot.
  Following bob2 = stop.m_bob;
  bob2.OnStream(Wire(*stop.m_rekey.m_end), stop.m_t);
  TEST(bob2.IsStale() && bob2.Position(), ("stop, end first: the position is kept, stale"));
  Deliver(stop.m_rekey.m_states, {{stop.m_bobA, &bob2}}, stop.m_t + 1);
  TEST(!bob2.Position() && !bob2.Grant(), ("the state without a grant then removes it"));
  // An end with nothing after it: the stale position goes after kEndGrace.
  Following bob3 = stop.m_bob;
  bob3.OnStream(Wire(*stop.m_rekey.m_end), stop.m_t);
  bob3.Tick(stop.m_t + kEndGrace - 1);
  TEST(bob3.Position(), ("kept during the grace period"));
  bob3.Tick(stop.m_t + kEndGrace);
  TEST(!bob3.Position(), ("dropped when the grace period is over"));
}

UNIT_TEST(Sharing_TimeLimitsAndEpochs)
{
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Paired const carol = Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0, false);
  int64_t const t = kT0 + 300;
  Sharer sharer(kRelaysA);
  Following carolView;
  Deliver(sharer.Start({{bob.m_inviterSide, 0}, {carol.m_inviterSide, t + 600}}, rng, t).m_states,
          {{carol.m_joinerSide, &carolView}}, t);
  TEST(!sharer.Tick(rng, t + 599), ("nothing changes before the time limit"));
  TEST(!carolView.OnStream(Wire(*sharer.PublishLocation(Fix(t), rng, t + 599)), t + 600) && !carolView.Grant(),
       ("the viewer enforces the time limit as well"));
  auto const expired = sharer.Tick(rng, t + 600);
  TEST(expired && expired->m_end, ());
  std::vector<std::pair<int64_t, size_t>> shape;
  for (auto const & state : expired->m_states)
    shape.emplace_back(state.second.m_kind, state.second.m_content.size());
  shape.emplace_back(expired->m_end->m_kind, expired->m_end->m_content.size());
  std::vector<std::pair<int64_t, size_t>> const expectedShape = {
      {kKindStored, 772}, {kKindStored, 772}, {kKindStored, 432}};
  TEST(shape == expectedShape && sharer.GetGrants().size() == 1 && sharer.GetGrants()[0].first == bob.m_inviterSide,
       ("at the time limit: states, then the end, and Carol is no longer a recipient"));

  // The epoch change re-keys too.
  std::string const oldPk = sharer.GetStream()->Pubkey();
  auto const rekey = sharer.Tick(rng, EpochEnd(EpochOf(t)));
  TEST(rekey && rekey->m_states.size() == 1 && rekey->m_end && sharer.GetStream()->Pubkey() != oldPk,
       ("a new stream at the epoch change"));
}

// --- Receiving rules: discard silently, and agree with a strict JSON parser -----------------------

using Members = std::vector<std::pair<std::string, std::string>>;  // name, JSON text of the value

/// An object laid out like Python's json.dumps() with its default separators.
std::string Object(Members const & members)
{
  std::string out = "{";
  for (auto const & [name, value] : members)
    out += (out.size() > 1 ? ", \"" : "\"") + name + "\": " + value;
  return out + "}";
}

/// `members` with `name` set to `value`: in place if present, else at the end.
Members With(Members members, std::string const & name, std::string const & value)
{
  for (auto & member : members)
  {
    if (member.first == name)
    {
      member.second = value;
      return members;
    }
  }
  members.emplace_back(name, value);
  return members;
}

std::string Quote(std::string const & s)
{
  return "\"" + s + "\"";
}

UNIT_TEST(Receiving_StatesAndLocations)
{
  auto & rng = ScenarioRng();
  int64_t const now = kT0 + 200;
  int64_t const e0 = EpochOf(now);
  Paired const erin = Pair("Alice", kRelaysA, "Erin", kRelaysB, kT0, false);
  Contact & erinA = *erin.m_joinerSide;
  Direction const towardsErin = erin.m_inviterSide->m_outgoing.At(e0);
  // A state from Alice to Erin whose plaintext is exactly `text`.
  auto const rawState = [&](std::string const & text, int64_t t)
  {
    std::string content = nip44::Encrypt(AsBytes(text), towardsErin.ConversationKey(), rng.Get<32>());
    return SignEvent(towardsErin.SigningKey(), t, kKindStored,
                     {{"d", ""}, {"expiration", std::to_string(EpochEnd(e0) + kControlGrace)}}, std::move(content),
                     rng);
  };

  Bytes junk = {0x02};
  Bytes const filler = rng.GetBytes(200);
  junk.insert(junk.end(), filler.begin(), filler.end());
  nostr::Event const garbage =
      SignEvent(towardsErin.SigningKey(), now + 20, kKindStored,
                {{"d", ""}, {"expiration", std::to_string(now + 9999)}}, Base64Encode(junk), rng);
  TEST(!ReadControl(erinA, Wire(garbage), now + 21), ("an undecryptable state is discarded silently"));

  Stream const stream = Stream::Create(rng);
  std::string const key = Base64Encode(stream.m_key);
  int64_t seq = 1000;
  std::string const relays = "[\"wss://nos.lol\", \"wss://nostr.mom\", \"wss://relay.primal.net\"]";
  auto const state = [&]()
  {
    ++seq;
    return Members{{"t", "\"state\""}, {"seq", std::to_string(seq)}, {"ts", std::to_string(now)}, {"relays", relays}};
  };
  auto const share = [&](std::string const & until, std::string const & pk, std::string const & k)
  { return Object({{"until", until}, {"pk", Quote(pk)}, {"key", Quote(k)}}); };
  std::string const goodShare = share("0", stream.Pubkey(), key);
  TEST(ReadControl(erinA, Wire(rawState(Object(With(state(), "share", goodShare)), now + 22)), now + 22),
       ("a well-formed state is accepted"));

  // The dot colour is cosmetic. A short string is kept, whatever the name (the app ignores names it does not
  // know); one of another type or size is ignored, not the state with its grant (§8).
  std::vector<std::tuple<std::string, std::string, std::optional<std::string>>> const colors = {
      {"a name", Quote("teal"), "teal"},
      {"a name of a later version", Quote("mauve"), "mauve"},
      {"32 bytes", Quote(std::string(32, 'x')), std::string(32, 'x')},
      {"33 bytes", Quote(std::string(33, 'x')), std::nullopt},
      {"empty", Quote(""), std::nullopt},
      {"a number", "7", std::nullopt},
      {"null", "null", std::nullopt},
  };
  for (auto const & [what, value, kept] : colors)
  {
    auto const decoded = DecodePlaintext(AsBytes(Object(With(With(state(), "share", goodShare), "color", value))));
    auto const parsed = decoded ? ParseState(*decoded) : std::nullopt;
    TEST(parsed && parsed->m_share && parsed->m_color == kept, (what));
  }

  std::string upperPk = stream.Pubkey();
  std::transform(upperPk.begin(), upperPk.end(), upperPk.begin(),
                 [](char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); });
  Members duplicate = state();
  duplicate.emplace_back("seq", "1");
  std::vector<std::pair<std::string, std::string>> const bad = {
      {"NaN", Object(With(state(), "ts", "NaN"))},
      {"Infinity", Object(With(state(), "ts", "Infinity"))},
      {"number overflow", Object(With(state(), "ts", "1e400"))},
      {"integer beyond 2^53", Object(With(state(), "ts", "9007199254740992"))},
      {"float as integer", Object(With(state(), "ts", std::to_string(now) + ".0"))},
      {"bool as integer", Object(With(state(), "seq", "true"))},
      {"duplicate member", Object(duplicate)},
      {"unpaired surrogate", Object(With(state(), "x", "\"\\ud800\""))},
      {"invalid UTF-8", Object(With(state(), "x", "\"\xff\""))},
      {"share.pk not hex", Object(With(state(), "share", share("0", std::string(64, 'Z'), key)))},
      {"share.pk upper case", Object(With(state(), "share", share("0", upperPk, key)))},
      {"share.pk off the curve", Object(With(state(), "share", share("0", std::string(64, '0'), key)))},
      {"share.key 31 bytes",
       Object(With(state(), "share", share("0", stream.Pubkey(), Base64Encode(rng.GetBytes(31)))))},
      {"share.key non-canonical",
       Object(With(state(), "share", share("0", stream.Pubkey(), key.substr(0, key.size() - 2) + "B=")))},
      {"share.until negative", Object(With(state(), "share", share("-1", stream.Pubkey(), key)))},
      {"share.until bool", Object(With(state(), "share", share("false", stream.Pubkey(), key)))},
      {"share missing key", Object(With(state(), "share", Object({{"until", "0"}, {"pk", Quote(stream.Pubkey())}})))},
      {"relays ws://", Object(With(state(), "relays", "[\"ws://nos.lol\"]"))},
  };
  for (auto const & [what, text] : bad)
  {
    int64_t const t = now + 23 + static_cast<int64_t>(what.size());
    auto const decoded = DecodePlaintext(AsBytes(text));
    TEST(!decoded || !ParseState(*decoded), ("refused by the field checks:", what));
    TEST(!ReadControl(erinA, Wire(rawState(text, t)), t), ("state discarded:", what));
  }
  TEST(!json::ParseProfile(AsBytes(R"({"t":"x","a":-Infinity})")), ("the profile refuses -Infinity"));
  auto const ordinary = json::ParseProfile(AsBytes(R"({"t":"x","a":-0.5,"b":9007199254740991})"));
  TEST(ordinary && ordinary->Get("a")->AsNumber() == -0.5 && ordinary->Get("b")->AsInt() == kMaxJsonInt,
       ("ordinary numbers are kept"));

  Share const grant{0, stream.Pubkey(), stream.m_key};
  auto const rawLoc = [&](std::string const & text, int64_t t)
  {
    std::string content = nip44::Encrypt(AsBytes(text), stream.m_key, rng.Get<32>());
    return SignEvent(stream.m_secret, t, kKindStored, {{"d", ""}, {"expiration", std::to_string(t + kTtlLocation)}},
                     std::move(content), rng);
  };
  Members const okLoc = {{"t", "\"loc\""}, {"seq", "50"}, {"ts", "1"}, {"lat", "1.5"}, {"lon", "-2"}, {"acc", "3"}};
  TEST(ReadStream(grant, rawLoc(Object(okLoc), now + 60), 0, now + 60), ("a well-formed location is accepted"));
  std::vector<std::tuple<std::string, std::string, std::string>> const badLoc = {
      {"lat 91", "lat", "91"},      {"lon -181", "lon", "-181"},
      {"acc -1", "acc", "-1"},      {"brg 360", "brg", "360"},
      {"spd -1", "spd", "-1"},      {"seq 0", "seq", "0"},
      {"seq bool", "seq", "true"},  {"lat string", "lat", "\"1\""},
      {"low not bool", "low", "1"}, {"nav.dest too long", "nav", Object({{"dest", Quote(std::string(49, 'x'))}})},
  };
  for (auto const & [what, name, value] : badLoc)
  {
    std::string const text = Object(With(okLoc, name, value));
    auto const decoded = DecodePlaintext(AsBytes(text));
    TEST(!decoded || !ParseStreamMessage(*decoded), ("refused by the field checks:", what));
    TEST(!ReadStream(grant, rawLoc(text, now + 61), 0, now + 61), ("location discarded:", what));
  }
  TEST(!ReadStream(grant, rawLoc(R"({"t":"end","seq":51})", now + 62), 0, now + 62),
       ("an end without ts is discarded"));
}
}  // namespace sharing_tests
