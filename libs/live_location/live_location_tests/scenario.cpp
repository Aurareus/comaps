#include "live_location/live_location_tests/scenario.hpp"

#include "testing/testing.hpp"

#include "live_location/protocol/constants.hpp"

#include <algorithm>

#include <jansson.h>

namespace live_location_tests
{
using namespace live_location;

Relays const kRelaysA = {"wss://nos.lol", "wss://nostr.mom", "wss://relay.primal.net"};
Relays const kRelaysB = {"wss://nos.lol", "wss://relay.nostr.net"};

crypto::Rng & ScenarioRng()
{
  static crypto::TestRng rng(AsBytes("scenario"));
  return rng;
}

nostr::Event Wire(nostr::Event const & event)
{
  std::string const text = nostr::ToJson(event);
  json_error_t error;
  json_t * root = json_loadb(text.data(), text.size(), 0, &error);
  TEST(root != nullptr, (text));
  auto out = nostr::FromJson(root);
  json_decref(root);
  TEST(out, (text));
  return *out;
}

void ModelRelay::Publish(nostr::Event const & event)
{
  auto const key = std::make_tuple(event.m_pubkey, event.m_kind, event.TagValue("d").value_or(""));
  auto const it = m_slots.find(key);
  if (it == m_slots.end() || event.m_createdAt > it->second.m_createdAt ||
      (event.m_createdAt == it->second.m_createdAt && event.m_id < it->second.m_id))
  {
    m_slots.insert_or_assign(key, event);
  }
}

std::vector<nostr::Event> ModelRelay::Query(std::set<std::string> const * authors,
                                            std::optional<std::string> const & pTag, std::optional<int64_t> now) const
{
  std::vector<nostr::Event> out;
  for (auto const & slot : m_slots)
  {
    nostr::Event const & e = slot.second;
    if (authors != nullptr && authors->count(e.m_pubkey) == 0)
      continue;
    if (pTag && e.TagValue("p") != *pTag)
      continue;
    if (now)
    {
      auto const exp = e.TagValue("expiration");
      if (exp && std::stoll(*exp) <= *now)
        continue;
    }
    out.push_back(Wire(e));
  }
  std::sort(out.begin(), out.end(), [](nostr::Event const & a, nostr::Event const & b)
  { return std::tie(a.m_createdAt, a.m_id) < std::tie(b.m_createdAt, b.m_id); });
  return out;
}

namespace
{
template <typename Party>
std::vector<Outcome> GoOnline(Party & party, std::vector<nostr::Event> const & events, ModelRelay & relay, int64_t now)
{
  std::vector<Outcome> outcomes;
  for (auto const & event : events)
  {
    std::optional<Outcome> out;
    try
    {
      out = party.OnEvent(event, ScenarioRng(), now);
    }
    catch (PairingOutOfOrder const &)
    {
      continue;  // held until due
    }
    if (out)
    {
      if (out->m_publish)
        relay.Publish(*out->m_publish);
      outcomes.push_back(std::move(*out));
    }
  }
  return outcomes;
}
}  // namespace

std::vector<Outcome> Online(Inviter & inviter, ModelRelay & relay, int64_t now)
{
  return GoOnline(inviter, relay.Query(nullptr, ToHex(inviter.GetInvite().m_ipk)), relay, now);
}

std::vector<Outcome> Online(Joiner & joiner, ModelRelay & relay, int64_t now)
{
  std::string const ipk = ToHex(joiner.GetInvite().m_ipk);
  std::set<std::string> const inviter = {ipk};
  auto events = relay.Query(nullptr, ipk);
  auto fromInviter = relay.Query(&inviter);
  events.insert(events.end(), fromInviter.begin(), fromInviter.end());
  std::sort(events.begin(), events.end(), [](nostr::Event const & a, nostr::Event const & b)
  { return std::tie(a.m_createdAt, a.m_id) < std::tie(b.m_createdAt, b.m_id); });
  return GoOnline(joiner, events, relay, now);
}

std::unique_ptr<Joiner> JoinerStarts(std::string const & link, std::string const & name, ModelRelay & relay,
                                     int64_t now)
{
  auto joiner = std::make_unique<Joiner>(*Invite::FromLink(link), name, kRelaysB, ScenarioRng(), now);
  relay.Publish(joiner->CommitEvent(ScenarioRng(), now));
  return joiner;
}

Paired Pair(std::string const & inviterName, Relays const & inviterRelays, std::string const & joinerName,
            Relays const & joinerRelays, int64_t now, bool checksOn)
{
  auto & rng = ScenarioRng();
  Paired p;
  p.m_relay = std::make_shared<ModelRelay>();
  ModelRelay & relay = *p.m_relay;
  p.m_inviter = std::make_shared<Inviter>(inviterRelays, rng, now);
  p.m_link = p.m_inviter->GetInvite().Link();
  p.m_joiner = std::make_shared<Joiner>(*Invite::FromLink(p.m_link), joinerName, joinerRelays, rng, now + 5);
  Inviter & inviter = *p.m_inviter;
  Joiner & joiner = *p.m_joiner;

  nostr::Event const m0 = joiner.CommitEvent(rng, now + 5);
  TEST_EQUAL(joiner.CommitEvent(rng, now + 6).m_id, m0.m_id, ("step 0 is made once; a retransmission resends it"));
  relay.Publish(m0);
  Online(inviter, relay, now + 6);  // step 1
  TEST(!inviter.OnEvent(Wire(m0), rng, now + 6), ("a copy of step 0 from another relay is ignored"));
  auto const out = Online(joiner, relay, now + 7);  // step 2
  TEST(out.size() == 1 && out[0].m_showCode && out[0].m_showCode->m_sas == joiner.Sas(),
       ("the joiner shows the code after step 2"));
  TEST(Online(joiner, relay, now + 7).empty(), ("copies of step 1 are not answered again"));
  auto const request = Online(inviter, relay, now + 8);
  TEST(request.size() == 1 && request[0].m_showCode, ());
  TEST(request[0].m_showCode->m_name == joinerName && request[0].m_showCode->m_sas == joiner.Sas(),
       ("the inviter sees the joiner's name and the same code"));
  auto const done = inviter.Decide(true, inviterName, inviterRelays, rng, now + 20);
  relay.Publish(*done.m_publish);
  p.m_inviterSide = done.m_contact;
  auto const finished = Online(joiner, relay, now + 21);
  TEST(finished.size() == 1 && finished[0].m_contact && finished[0].m_publish, ());
  p.m_joinerSide = finished[0].m_contact;
  Contact & ci = *p.m_inviterSide;
  Contact & cj = *p.m_joinerSide;
  if (!checksOn)
    return p;

  TEST(!ci.m_confirmed && cj.m_confirmed, ("the inviter waits for the joiner to confirm"));
  nostr::Event const & confirmation = *finished[0].m_publish;
  TEST(confirmation.m_kind == kKindStored && confirmation.m_pubkey == cj.m_outgoing.At(EpochOf(now + 21)).Pubkey(),
       ("the joiner publishes one state on the new channel when it accepts step 3"));
  auto const state = ReadControl(ci, Wire(confirmation), now + 22);
  TEST(state && !state->m_share && ci.m_confirmed,
       ("that share-less state confirms the contact on the inviter's side"));
  TEST(cj.m_joiner && !ci.m_joiner && cj.m_pairingEpoch == ci.m_pairingEpoch,
       ("both sides know the pairing epoch; only the joiner owes confirmations"));
  TEST(!ConfirmationDue(cj, now + 22) && !ConfirmationDue(ci, now + 22), ("the first confirmation covers its UTC day"));
  TEST_EQUAL(ci.m_sas, cj.m_sas, ("SAS agree"));
  TEST_EQUAL(ToHex(ci.m_outgoing.ChainKey()), ToHex(cj.m_incoming.ChainKey()), ("A->B chain keys agree"));
  TEST_EQUAL(ToHex(ci.m_incoming.ChainKey()), ToHex(cj.m_outgoing.ChainKey()), ("B->A chain keys agree"));
  TEST_NOT_EQUAL(ToHex(ci.m_outgoing.ChainKey()), ToHex(ci.m_incoming.ChainKey()), ("directions differ"));
  TEST(cj.m_name == inviterName && ci.m_name == joinerName, ("names exchanged"));
  TEST(cj.m_relays == inviterRelays && ci.m_relays == joinerRelays, ("relays exchanged"));
  TEST(!ci.m_verified && !cj.m_verified, ("contacts start unverified"));
  TEST(!inviter.HasSecrets() && !joiner.HasSecrets(),
       ("both sides erased the PSK, their pairing key, the ephemeral key, the Noise state and the roots"));
  TEST(!inviter.IsAborted() && !joiner.IsAborted(), ("both keep the MAC key, to watch until expiry"));
  TEST(Online(inviter, relay, now + 30).empty() && Online(joiner, relay, now + 30).empty(),
       ("watching after completion: nothing new, nothing flagged"));
  return p;
}

std::vector<State> ReadInbox(Contact & contact, ModelRelay const & relay, int64_t now)
{
  std::set<std::string> authors;
  for (auto const & entry : IncomingKeys(contact, now))
    authors.insert(entry.first);
  std::vector<State> out;
  for (auto const & event : relay.Query(&authors, {}, now))
    if (auto state = ReadControl(contact, event, now))
      out.push_back(std::move(*state));
  return out;
}
}  // namespace live_location_tests
