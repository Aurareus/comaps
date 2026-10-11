#include "testing/testing.hpp"

#include "live_location/live_location_tests/scenario.hpp"
#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/crypto/noise.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/stream.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <jansson.h>

// The scenarios of tools/python/live_location/test_protocol.py around the pairing and the channels,
// ported: codes, midnight, invite lifetimes, two-sided completion and confirmations, relay consent,
// envelope types, forward secrecy, signals and subscriptions.
namespace channel_tests
{
using namespace live_location;
using namespace live_location_tests;
using std::invalid_argument;  // TEST_THROW pastes its argument after "std::"
using std::logic_error;

std::set<std::string> Trusted(Relays const & own)
{
  std::set<std::string> trusted(own.begin(), own.end());
  trusted.insert(kDefaultRelays.begin(), kDefaultRelays.end());
  return trusted;
}

bool Contains(std::vector<std::string> const & keys, std::string const & key)
{
  return std::find(keys.begin(), keys.end(), key) != keys.end();
}

/// The three steps before the inviter's decision: step 0 was published by JoinerStarts().
void UpToDecision(Inviter & alice, Joiner & bob, ModelRelay & relay, int64_t now)
{
  Online(alice, relay, now + 1);
  Online(bob, relay, now + 2);
  Online(alice, relay, now + 3);
}

UNIT_TEST(Pairing_CodeDependsOnlyOnKeys)
{
  // Same PSK and ephemeral keys, different step 2 payloads (here the joiner's name): the handshake hash
  // differs, the code does not. With a code taken from the hash, a man in the middle could vary the step 2
  // payload it sends to the inviter until the inviter's code equals the joiner's (~1e6 cheap tries); taken
  // from the keys, it has nothing to vary.
  auto & rng = ScenarioRng();
  Key const psk = rng.Get<32>();
  Key const eInitiator = rng.Get<32>();
  Key const eResponder = rng.Get<32>();
  Bytes const prologue = Inviter(kRelaysA, rng, kT0).GetInvite().Prologue(ByteArray<32>{}, ByteArray<32>{});
  std::set<std::string> codes;
  std::set<std::string> hashes;
  for (std::string const name : {"Bob", "Bob ", "Bob  ", "Robert"})
  {
    noise::HandshakeState i(true, prologue, psk, eInitiator);
    noise::HandshakeState r(false, prologue, psk, eResponder);
    TEST(r.ReadMessage(*i.WriteMessage(EncodePlaintext(Pair1Json(), kSizeControl))), ());
    TEST(i.ReadMessage(*r.WriteMessage(EncodePlaintext(ToJson(Pair2{name, kRelaysB}), kSizeControl))), ());
    hashes.insert(ToHex(i.HandshakeHash()));
    codes.insert(SasDigits(i.Split().m_k1));
  }
  TEST(hashes.size() == 4 && codes.size() == 1, ("the code does not depend on the payloads; the handshake hash does"));
}

UNIT_TEST(Pairing_RewrittenLinkShowsDifferentCodes)
{
  // A link rewritten in transit (Mallory's own invite) gives a full man in the middle: the protocol cannot
  // see it, the codes differ, and the contacts stay unverified until the users compare them.
  auto & rng = ScenarioRng();
  Inviter alice(kRelaysA, rng, kT0);
  Inviter malloryInviter(kRelaysA, rng, kT0);
  Joiner bob(*Invite::FromLink(malloryInviter.GetInvite().Link()), "Bob", kRelaysB, rng, kT0);
  Joiner malloryJoiner(*Invite::FromLink(alice.GetInvite().Link()), "Bob", kRelaysB, rng, kT0);
  auto const toMallory = alice.OnEvent(Wire(malloryJoiner.CommitEvent(rng, kT0)), rng, kT0);
  malloryJoiner.OnEvent(Wire(*toMallory->m_publish), rng, kT0);
  auto const toBob = malloryInviter.OnEvent(Wire(bob.CommitEvent(rng, kT0)), rng, kT0);
  bob.OnEvent(Wire(*toBob->m_publish), rng, kT0);
  auto const shown = alice.OnEvent(Wire(*malloryJoiner.Step2()), rng, kT0);
  TEST(shown && shown->m_showCode && !bob.Sas().empty() && shown->m_showCode->m_sas != bob.Sas(),
       ("a man in the middle with a rewritten link: the two screens show different codes"));
}

UNIT_TEST(Pairing_AroundMidnight)
{
  auto & rng = ScenarioRng();
  {
    // The inviter's clock is 4 minutes ahead and it is already the next day there. e_p lags by the
    // accepted skew, so it is never in the joiner's future, and every channel operation works.
    int64_t const midnight = EpochEnd(EpochOf(kT0));
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, midnight + 60);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, midnight - 180);
    Online(alice, relay, midnight + 61);
    Online(*bob, relay, midnight - 179);
    Online(alice, relay, midnight + 62);
    relay.Publish(*alice.Decide(true, "Alice", kRelaysA, rng, midnight + 63).m_publish);
    auto const out = Online(*bob, relay, midnight - 177);
    TEST(out.size() == 1 && out[0].m_contact, ());
    Contact & c = *out[0].m_contact;
    TEST_EQUAL(c.m_incoming.Epoch(), EpochOf(midnight - 177), ("the pairing epoch is not in the joiner's future"));
    TEST(!InboxFilters({out[0].m_contact}, rng.Get<32>(), EpochOf(midnight - 170), midnight - 170).empty() &&
             !StateEvent(c, kRelaysB, std::nullopt, rng, midnight - 170).m_id.empty() &&
             !WatchSignal(c, midnight, rng, midnight - 170).m_id.empty(),
         ("subscriptions, states and signals work right after pairing near midnight"));
  }
  {
    // A step 3 whose epoch lies in the joiner's future is refused (as an earlier inviter would have sent
    // it). Forged here with the inviter's pairing key and the split key the joiner holds until the end.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    UpToDecision(alice, *bob, relay, kT0);
    TEST(bob->K1(), ("the joiner holds the split keys between step 2 and the end of the pairing"));
    Pair3 future;
    future.m_ok = true;
    future.m_name = "Alice";
    future.m_relays = kRelaysA;
    future.m_epoch = EpochOf(kT0) + 1;
    std::string content = Seal(ToJson(future), kSizeControl, ConfirmKey(*bob->K1()), rng);
    relay.Publish(
        PairingEvent(alice.PairingSecretForVectors(), 3, alice.GetInvite(), std::move(content), rng, kT0 + 4));
    TEST(Throws<PairingAborted>([&] { Online(*bob, relay, kT0 + 5); }),
         ("the joiner refuses a pairing epoch in its future"));
  }
  {
    // A contact whose chain is ahead of the clock (the clock was set back) does not break the others.
    Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
    int64_t const e = EpochOf(kT0);
    auto const ahead =
        std::make_shared<Contact>("x", kRelaysA, Direction(e + 5, rng.Get<32>()), Direction(e + 5, rng.Get<32>()), "");
    auto const filters = InboxFilters({ahead, p.m_inviterSide}, rng.Get<32>(), e, kT0);
    TEST(filters.size() == 2 && filters[0].m_authors.size() == 8 &&
             Contains(filters[0].m_authors, p.m_inviterSide->m_incoming.At(e).Pubkey()),
         ("one contact ahead of the clock does not take down the inbox subscription"));
    TEST(!StateEvent(*ahead, kRelaysA, std::nullopt, rng, kT0).m_id.empty(),
         ("a chain ahead of the clock still signs"));
  }
}

UNIT_TEST(Pairing_InviteLifetimeAndRelayConsent)
{
  auto & rng = ScenarioRng();
  Inviter alice(kRelaysA, rng, kT0, 86400);
  TEST_THROW(Joiner(*Invite::FromLink(alice.GetInvite().Link()), "Late", kRelaysB, rng, kT0 + 86400 * 2),
             invalid_argument, ("an expired invite is refused"));

  // Invites live at most a day: the inviter chooses the relays the joiner watches until expiry, so a longer
  // life would let it keep a joiner's phone connecting to its relay (and learn its IP) for years.
  int64_t const tenYears = int64_t{10} * 365 * 86400;
  Relays const stalker = {"wss://stalker-relay.example"};
  TEST_THROW(Inviter(stalker, rng, kT0, tenYears), invalid_argument,
             ("an inviter cannot make an invite that lives over a day"));
  Invite const longLived{rng.Get<32>(), alice.GetInvite().m_ipk, kT0 + tenYears, stalker};
  TEST_THROW(Joiner(*Invite::FromLink(longLived.Link()), "Victim", kRelaysB, rng, kT0), invalid_argument,
             ("a joiner refuses an invite that expires more than a day ahead"));
  Invite const edge{rng.Get<32>(), alice.GetInvite().m_ipk, kT0 + kMaxInviteLifetime + kMaxFutureSkew, kRelaysA};
  TEST(!Throws<std::invalid_argument>([&] { Joiner(*Invite::FromLink(edge.Link()), "B", kRelaysB, rng, kT0); }),
       ("a day plus the accepted clock skew is still fine"));

  // Relay consent: only the user's own relays, the defaults and relays approved earlier are used without
  // asking; anything else a contact names needs the user's approval first.
  std::set<std::string> trusted = Trusted(kRelaysB);
  auto const split = SplitRelays({"wss://nos.lol", "wss://stalker-relay.example", "wss://relay.nostr.net"}, trusted);
  TEST(split.first == Relays({"wss://nos.lol", "wss://relay.nostr.net"}) && split.second == stalker,
       ("relays other than the user's own, the default and the approved ones need asking"));
  trusted.insert(stalker[0]);
  auto const approved = SplitRelays(stalker, trusted);
  TEST(approved.first == stalker && approved.second.empty(), ("an approved relay is used without asking again"));
}

UNIT_TEST(Pairing_TwoSidedCompletion)
{
  auto & rng = ScenarioRng();
  {
    // Alice decides near the end of the invite's life, and Bob opens CoMaps only after it expired: step 3
    // has expired with the invite, Bob never completes, and Alice's contact stays unconfirmed (the app
    // shows "Waiting for Bob", and offers to remove it once the week is over).
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0, 86400);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    UpToDecision(alice, *bob, relay, kT0);
    int64_t const end = alice.GetInvite().m_expiresAt;
    relay.Publish(*alice.Decide(true, "Alice", kRelaysA, rng, end - 60).m_publish);
    TEST(Online(*bob, relay, end + 600).empty() && !bob->GetContact() && !alice.GetContact()->m_confirmed,
         ("the joiner back after expiry: no contact on its side, and the inviter's stays unconfirmed"));
    Contact const & waiting = *alice.GetContact();
    int64_t const weekOver = EpochEnd(waiting.m_pairingEpoch + kConfirmEpochs) + kControlGrace;
    TEST(!OfferRemoval(waiting, weekOver - 1) && OfferRemoval(waiting, weekOver),
         ("removal is offered once the week is over, not before"));
    TEST_THROW(alice.Decide(true, "Alice", kRelaysA, rng, end + 5), logic_error, ("Decide() twice is refused"));
  }
  {
    // Decide() after expiry is refused: relays would refuse the step 3, and the joiner has stopped.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    UpToDecision(alice, *bob, relay, kT0);
    TEST_THROW(alice.Decide(true, "Alice", kRelaysA, rng, alice.GetInvite().m_expiresAt), invalid_argument,
               ("Decide() is refused once the invite has expired"));
  }
  {
    // Bob taps "They differ" (his app aborts): he never confirms, so Alice's contact stays unconfirmed.
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    UpToDecision(alice, *bob, relay, kT0);
    bob->Abort();
    relay.Publish(*alice.Decide(true, "Alice", kRelaysA, rng, kT0 + 4).m_publish);
    TEST(Online(*bob, relay, kT0 + 5).empty() && !alice.GetContact()->m_confirmed,
         ("\"They differ\" on the joiner: no confirmation, and the inviter's contact stays unconfirmed"));
    TEST_EQUAL(bob->CommitEvent(rng, kT0 + 6).m_id, bob->Step0()->m_id,
               ("an aborted joiner can still resend its old step 0, nothing new"));
    Joiner fresh(*Invite::FromLink(Inviter(kRelaysA, rng, kT0).GetInvite().Link()), "B", kRelaysB, rng, kT0 + 6);
    fresh.Abort();
    TEST_THROW(fresh.CommitEvent(rng, kT0 + 6), logic_error, ("a joiner aborted before step 0 makes none"));
  }
  {
    ModelRelay relay;
    Inviter alice(kRelaysA, rng, kT0);
    auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, kT0);
    UpToDecision(alice, *bob, relay, kT0);
    alice.Abort();
    TEST_THROW(alice.Decide(true, "Alice", kRelaysA, rng, kT0 + 4), logic_error,
               ("Decide() is refused after an abort"));
  }
}

UNIT_TEST(Pairing_ConfirmationExpiresUnread)
{
  // The confirmation can expire before the inviter reads it. The review's scenario: Bob accepts step 3 at
  // 23:30 UTC, his confirmation expires at 01:00, and Alice's app, next opened at 08:00, finds nothing.
  // Bob's app sends its current state again on each later UTC day it runs, through epoch e_p + 7.
  auto & rng = ScenarioRng();
  int64_t const day = EpochOf(kT0) + 10;
  int64_t const t2330 = EpochEnd(day) - 1800;
  ModelRelay relay;   // the invite's relay
  ModelRelay inboxA;  // Alice's inbox relay
  Inviter alice(kRelaysA, rng, t2330 - 600, 3600);
  auto bob = JoinerStarts(alice.GetInvite().Link(), "Bob", relay, t2330 - 600);
  Online(alice, relay, t2330 - 590);
  Online(*bob, relay, t2330 - 580);
  Online(alice, relay, t2330 - 570);
  relay.Publish(*alice.Decide(true, "Alice", kRelaysA, rng, t2330 - 60).m_publish);
  auto const finished = Online(*bob, relay, t2330);
  TEST(finished.size() == 1 && finished[0].m_publish && finished[0].m_contact, ());
  inboxA.Publish(*finished[0].m_publish);
  Contact & aB = *alice.GetContact();
  ContactPtr const & bA = finished[0].m_contact;
  TEST(bA->m_pairingEpoch == day && finished[0].m_publish->TagValue("expiration") == std::to_string(t2330 + 5400),
       ("a confirmation sent at 23:30 is readable for 1.5 h"));
  int64_t t = EpochEnd(day) + 8 * 3600;  // 08:00 the next day
  TEST(ReadInbox(aB, inboxA, t).empty() && !aB.m_confirmed, ("Alice at 08:00: nothing to read, Bob still waiting"));
  TEST(!OfferRemoval(aB, t), ("\"waiting\" is a label: no removal offered during the week"));
  t = EpochEnd(day) + 12 * 3600;  // Bob's app runs at 12:00
  TEST(ConfirmationDue(*bA, t), ("on a later UTC day the joiner confirms again"));
  inboxA.Publish(Sharer(kRelaysB).CurrentState(bA, rng, t));
  TEST(!ConfirmationDue(*bA, t + 60), ("once per UTC day"));
  auto const states = ReadInbox(aB, inboxA, t + 3600);  // Alice at 13:00
  TEST(states.size() == 1 && !states[0].m_share && aB.m_confirmed, ("Alice reads it at 13:00: Bob is confirmed"));
  std::vector<int64_t> sent;
  for (int64_t e = day + 2; e < day + 12; ++e)
  {
    int64_t const at = e * kEpochSeconds + 7200;
    if (ConfirmationDue(*bA, at))
    {
      Sharer(kRelaysB).CurrentState(bA, rng, at);
      sent.push_back(e);
    }
  }
  std::vector<int64_t> expected;
  for (int64_t e = day + 2; e <= day + kConfirmEpochs; ++e)
    expected.push_back(e);
  TEST(sent == expected, ("daily through epoch e_p + 7, then never again"));
  TEST(!OfferRemoval(aB, EpochEnd(day + 30)), ("a confirmed contact is never offered for removal"));
}

UNIT_TEST(Pairing_WaitingDoesNotBlockSharing)
{
  auto & rng = ScenarioRng();
  {
    // Any message from the joiner confirms, a watch signal included. Bob's confirmation is lost here;
    // Alice shares with him anyway, and his first watch signal confirms him.
    Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
    int64_t const t = kT0 + 600;
    Following view;
    Deliver(Sharer(kRelaysA).Start({{p.m_inviterSide, 0}}, rng, t).m_states, {{p.m_joinerSide, &view}}, t + 1);
    TEST(!p.m_inviterSide->m_confirmed && view.Grant(),
         ("Alice can share with a waiting contact, and Bob receives it"));
    TEST(ReadSignal(*p.m_inviterSide, Wire(WatchSignal(*p.m_joinerSide, t + 120, rng, t + 2)), t + 3) &&
             p.m_inviterSide->m_confirmed,
         ("Bob's watch signal confirms him"));
  }
  {
    // The daily confirmation is the joiner's CURRENT state. While Bob shares with Alice it carries his
    // grant: a state without one would end his share.
    Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
    Contact & aB = *p.m_inviterSide;
    ContactPtr const & bA = p.m_joinerSide;
    int64_t const ep = bA->m_pairingEpoch;
    int64_t t = EpochEnd(ep) + 600;
    Sharer bobSharer(kRelaysB);
    Following aliceView;
    Deliver(bobSharer.Start({{bA, 0}}, rng, t).m_states, {{p.m_inviterSide, &aliceView}}, t);
    TEST(aB.m_confirmed && !ConfirmationDue(*bA, t + 60), ("a share's states count as the day's confirmation"));
    t = EpochEnd(ep + 1) + 30;
    TEST(bobSharer.Tick(rng, t) && !ConfirmationDue(*bA, t + 1), ("so does the re-key at the new epoch"));
    t = EpochEnd(ep + 2) + 30;  // the check comes before the day's re-key
    TEST(ConfirmationDue(*bA, t), ("a confirmation is due before the re-key"));
    auto const st = ReadControl(aB, Wire(bobSharer.CurrentState(bA, rng, t)), t);
    TEST(st, ());
    aliceView.OnState(*st, t);
    TEST(st->m_share && st->m_share->m_pk == bobSharer.GetStream()->Pubkey() && aliceView.Grant() &&
             aliceView.Grant()->m_pk == st->m_share->m_pk,
         ("it carries the current grant, so Alice keeps following"));
  }
  {
    // Removal is offered exactly when the latest confirmation the joiner can owe has expired.
    Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
    Contact & aB = *p.m_inviterSide;
    int64_t const weekOver = EpochEnd(aB.m_pairingEpoch + kConfirmEpochs) + kControlGrace;
    nostr::Event const last = Sharer(kRelaysB).CurrentState(
        p.m_joinerSide, rng, EpochEnd(p.m_joinerSide->m_pairingEpoch + kConfirmEpochs) - 1);
    TEST(last.TagValue("expiration") == std::to_string(weekOver) && !OfferRemoval(aB, weekOver - 1) &&
             OfferRemoval(aB, weekOver),
         ("removal is offered from the expiry of the last owed confirmation on"));
    TEST(ReadControl(aB, Wire(last), weekOver - 1) && !OfferRemoval(aB, weekOver),
         ("read in its last second, that confirmation still counts"));
  }
}

UNIT_TEST(Invites_RelaysAndEncoding)
{
  // Relays: wss:// only; ws:// only to a loopback host.
  for (std::string const url : {"wss://nos.lol", "ws://127.0.0.1:7777", "ws://localhost", "ws://[::1]:7777/"})
    TEST(IsValidRelayList({url}), ("relay URL accepted:", url));
  std::vector<std::string> const refused = {"ws://nos.lol",
                                            "ws://192.168.1.2:7777",
                                            "ws://127.0.0.1.example.com",
                                            "ws://localhost@evil.example",
                                            "http://nos.lol",
                                            "wss://" + std::string(60, 'x'),
                                            "wss://",
                                            "wss://nos .lol",
                                            "wss://n\xc3\xb6s.lol"};
  for (auto const & url : refused)
    TEST(!IsValidRelayList({url}), ("relay URL refused:", url));

  auto & rng = ScenarioRng();
  ByteArray<32> const ipk = Inviter(kRelaysA, rng, kT0).GetInvite().m_ipk;
  Invite const plain{rng.Get<32>(), ipk, kT0 + 600, {"ws://nos.lol"}};  // Encode() does not check
  TEST(!Invite::FromLink(plain.Link()), ("an invite with a ws:// relay is refused"));
  TEST(!Invite::FromLink(Invite{rng.Get<32>(), ByteArray<32>{}, kT0, kRelaysA}.Link()),
       ("an invite whose pairing key is not a curve point is refused"));
  Invite const shortInvite{rng.Get<32>(), ipk, kT0 + 600, {"wss://ab.io"}};  // 82 bytes: 4 unused bits at the end
  std::string const link = shortInvite.Link();
  std::string altered = link;
  altered.back() = static_cast<char>(altered.back() + 1);
  TEST(shortInvite.Encode().size() % 3 == 1 && !Invite::FromLink(altered) && Invite::FromLink(link) &&
           Invite::FromLink(link)->m_relays == Relays{"wss://ab.io"},
       ("non-canonical base64url in an invite is refused"));
}

std::optional<nostr::Event> ParseEvent(std::string const & text)
{
  json_error_t error;
  json_t * root = json_loadb(text.data(), text.size(), 0, &error);
  if (root == nullptr)
    return {};
  auto event = nostr::FromJson(root);
  json_decref(root);
  return event;
}

UNIT_TEST(Events_EnvelopeTypes)
{
  // Envelope types (§12 item 1). Python serialises the string "d0" exactly like the tag ["d", "0"], so a
  // step 0 whose first tag is that string keeps a valid id and signature; a typed parser refuses it.
  // Likewise uppercase hex, and content that is not a string.
  auto & rng = ScenarioRng();
  Inviter inviter(kRelaysA, rng, kT0);
  Joiner joiner(*Invite::FromLink(inviter.GetInvite().Link()), "Bob", kRelaysB, rng, kT0);
  nostr::Event const m0 = joiner.CommitEvent(rng, kT0);
  std::string const text = nostr::ToJson(m0);
  auto const parsed = ParseEvent(text);
  TEST(parsed && PairingStep(*parsed, inviter.GetInvite(), kT0) == 0, ("a well-typed step 0 passes"));
  auto const replaced = [&](std::string const & from, std::string const & to)
  {
    std::string out = text;
    size_t const pos = out.find(from);
    TEST(pos != std::string::npos, (from));
    return out.replace(pos, from.size(), to);
  };
  std::string upperSig = m0.m_sig;
  std::transform(upperSig.begin(), upperSig.end(), upperSig.begin(),
                 [](char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); });
  TEST(!ParseEvent(replaced("[\"d\",\"0\"]", "\"d0\"")), ("a tag given as a string is refused"));
  TEST(!ParseEvent(replaced(m0.m_sig, upperSig)), ("uppercase hex in a signature is refused"));
  TEST(!ParseEvent(replaced("\"content\":\"" + m0.m_content + "\"", "\"content\":5")),
       ("content that is not a string is refused"));
}

UNIT_TEST(Channels_ForwardSecrecy)
{
  auto & rng = ScenarioRng();
  Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Contact & aBob = *p.m_inviterSide;
  Contact & bobA = *p.m_joinerSide;
  int64_t const now = kT0 + 200;
  int64_t const e = EpochOf(now);
  nostr::Event const state = StateEvent(aBob, kRelaysA, std::nullopt, rng, now);
  std::string const chainKey = ToHex(bobA.m_incoming.At(e).ChainKey());
  Ratchet(bobA, EpochEnd(e) + kControlGrace - 1);
  TEST_EQUAL(bobA.m_incoming.Epoch(), e, ("the keys of the previous epoch are kept during the grace hour"));
  ReadControl(bobA, Wire(state), EpochEnd(e) + kControlGrace);  // any use ratchets
  TEST(bobA.m_incoming.Epoch() == e + 1 && bobA.m_outgoing.Epoch() == e + 1,
       ("the chain keys ratchet when the hour is over"));
  TEST(Throws<std::invalid_argument>([&] { bobA.m_incoming.At(e); }) && ToHex(bobA.m_incoming.ChainKey()) != chainKey,
       ("an erased epoch cannot be derived again from what the device stores"));
  Direction const next = aBob.m_outgoing.At(e + 1);
  TEST_NOT_EQUAL(next.Pubkey(), aBob.m_outgoing.At(e).Pubkey(), ("the channel key changes every epoch"));
  TEST(Throws<std::invalid_argument>([&] { next.At(e); }), ("the ratchet cannot go backwards"));
  int64_t const later = EpochEnd(e) + 10;
  Stream const stream = Stream::Create(rng);
  nostr::Event const grant = StateEvent(aBob, kRelaysA, Share{0, stream.Pubkey(), stream.m_key}, rng, later);
  TEST(ReadControl(bobA, Wire(grant), later + 1), ("a state of the next epoch is readable"));
}

UNIT_TEST(Channels_Signals)
{
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Paired const carol = Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0, false);
  Contact & aBob = *bob.m_inviterSide;
  Contact & bobA = *bob.m_joinerSide;
  int64_t const later = EpochEnd(EpochOf(kT0)) + 10;
  nostr::Event const signal = WatchSignal(bobA, later + 120, rng, later + 10);
  auto const watch = ReadSignal(aBob, Wire(signal), later + 11);
  TEST(watch && watch->m_until == later + 120 && watch->m_ts == later + 10, ("Alice reads Bob's watch signal"));
  TEST(!ReadSignal(*carol.m_inviterSide, Wire(signal), later + 11), ("a watch signal is bound to its channel"));
  TEST(!ReadSignal(aBob, Wire(signal), later + 10 + kSignalMaxAge + 1), ("a stale signal is ignored"));
  Direction const towardsAlice = bobA.m_outgoing.At(EpochOf(later));
  Bytes junk = {0x02};
  Bytes const filler = rng.GetBytes(150);
  junk.insert(junk.end(), filler.begin(), filler.end());
  nostr::Event const junkSignal =
      SignEvent(towardsAlice.SigningKey(), later + 12, kKindSignal, {}, Base64Encode(junk), rng);
  TEST(!ReadSignal(aBob, Wire(junkSignal), later + 12), ("an undecryptable signal is discarded silently"));
}

UNIT_TEST(Channels_ListeningRelayNeedsConsent)
{
  // Relay consent meets the single listening connection (D17). Alice lists her own relay first, so while
  // she shares and nobody watches, her app listens only there. Bob's app may not use that relay, so his
  // watch signals go only to her other one, and live updates never start. Relay lists keep the sender's
  // order, so Bob's app can tell which relay live updates need, and ask for it.
  auto & rng = ScenarioRng();
  Paired const p = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Contact & aBob = *p.m_inviterSide;
  Contact & bobA = *p.m_joinerSide;
  int64_t const later = EpochEnd(EpochOf(kT0)) + 10;
  Relays const aliceList = {"wss://relay.alice.example", "wss://nos.lol"};
  std::map<std::string, ModelRelay> store;  // one model relay per URL
  std::set<std::string> bobTrusted = Trusted(kRelaysB);
  auto const st = ReadControl(bobA, Wire(StateEvent(aBob, aliceList, std::nullopt, rng, later + 20)), later + 20);
  TEST(st && st->m_relays == aliceList, ("a state carries the sender's relays, in its order"));
  for (auto const & url : SplitRelays(st->m_relays, bobTrusted).first)
    store[url].Publish(WatchSignal(bobA, later + 200, rng, later + 21));
  TEST(store[aliceList[0]].Query().empty() && store["wss://nos.lol"].Query().size() == 1,
       ("Bob's watch signal misses the only relay Alice listens on: no live updates"));
  TEST(MissingListeningRelay(st->m_relays, bobTrusted) == std::optional<std::string>(aliceList[0]),
       ("Bob's app knows which relay live updates need"));
  bobTrusted.insert(aliceList[0]);  // Bob allows it
  for (auto const & url : SplitRelays(st->m_relays, bobTrusted).first)
    store[url].Publish(WatchSignal(bobA, later + 260, rng, later + 81));
  auto const heard = store[aliceList[0]].Query();
  TEST(!MissingListeningRelay(st->m_relays, bobTrusted) && heard.size() == 1 && ReadSignal(aBob, heard[0], later + 82),
       ("once allowed, his signals reach her listening relay"));
  Relays const defaultFirst(aliceList.rbegin(), aliceList.rend());
  TEST(!MissingListeningRelay(defaultFirst, Trusted({})), ("a default relay first: nothing to ask"));
}

UNIT_TEST(Channels_InboxSubscriptions)
{
  auto & rng = ScenarioRng();
  Paired const bob = Pair("Alice", kRelaysA, "Bob", kRelaysB, kT0, false);
  Paired const carol = Pair("Alice", kRelaysA, "Carol", kRelaysB, kT0, false);
  std::vector<ContactPtr> const contacts = {bob.m_inviterSide, carol.m_inviterSide};
  int64_t const later = EpochEnd(EpochOf(kT0)) + 10;
  int64_t const e = EpochOf(later);
  Key const seed = rng.Get<32>();
  auto const filters = InboxFilters(contacts, seed, e, later);
  TEST_EQUAL(filters.size(), 2, ());
  std::vector<std::string> const & authors = filters[0].m_authors;
  TEST(filters[0].m_kinds == std::vector<int64_t>{kKindStored} &&
           filters[1].m_kinds == std::vector<int64_t>{kKindSignal} && filters[1].m_authors == authors &&
           !filters[0].m_since && filters[1].m_since == later - kSignalMaxAge,
       ("one author list for states and signals: relays cannot tell recipients from other contacts"));
  TEST(authors.size() == 8 && std::is_sorted(authors.begin(), authors.end()),
       ("inbox authors padded to 8 with decoys, sorted"));
  TEST(Contains(authors, bob.m_inviterSide->m_incoming.At(e).Pubkey()) &&
           Contains(authors, carol.m_inviterSide->m_incoming.At(e).Pubkey()),
       ("the real keys are included"));
  TEST(InboxFilters(contacts, seed, e, later + 500)[0].m_authors == authors,
       ("decoys are stable within the epoch (reconnecting reveals nothing)"));
  auto const next = InboxFilters(contacts, seed, e + 1, later)[0].m_authors;
  TEST(std::none_of(next.begin(), next.end(), [&](std::string const & k) { return Contains(authors, k); }),
       ("nothing in common between two epochs' filters"));
  TEST(!Contains(authors, bob.m_inviterSide->m_incoming.At(e + 1).Pubkey()), ("a filter holds keys of one epoch only"));

  auto const dummies = [&](size_t n)
  {
    std::vector<ContactPtr> out;
    for (size_t i = 0; i < n; ++i)
      out.push_back(
          std::make_shared<Contact>("x", kRelaysA, Direction(e, rng.Get<32>()), Direction(e, rng.Get<32>()), ""));
    return out;
  };
  TEST_EQUAL(InboxFilters(dummies(9), seed, e, later)[0].m_authors.size(), 16, ("9 contacts: 16 keys"));
  std::vector<size_t> sizes;
  for (auto const & filter : InboxFilters(dummies(60), seed, e, later))
    sizes.push_back(filter.m_authors.size());
  TEST(sizes == std::vector<size_t>({50, 50, 14, 14}), ("64 keys split into filters of at most 50"));
  TEST(InboxFilters({}, seed, e, later).empty(), ("no contacts, no subscription"));
}
}  // namespace channel_tests
