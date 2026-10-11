#include "live_location/protocol/channel.hpp"

#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"

#include <algorithm>
#include <cstdio>
#include <stdexcept>

namespace live_location
{
namespace
{
Bytes WithU32(Bytes prefix, uint32_t v)
{
  for (int shift = 24; shift >= 0; shift -= 8)
    prefix.push_back(static_cast<uint8_t>(v >> shift));
  return prefix;
}
}  // namespace

Direction Direction::FromRoot(Key const & root, int64_t pairingEpoch)
{
  return Direction(pairingEpoch,
                   crypto::HkdfExpandTo<32>(root, WithU32(Label("ck"), static_cast<uint32_t>(pairingEpoch))));
}

Direction Direction::At(int64_t epoch) const
{
  if (epoch < m_epoch)
    throw std::invalid_argument("epoch in the past: its keys were ratcheted away");
  Key ck = m_chainKey;
  Bytes const info = Label("ck-next");
  for (int64_t e = m_epoch; e < epoch; ++e)
    ck = crypto::HkdfExpandTo<32>(ck, info);
  return Direction(epoch, ck);
}

void Direction::Advance(int64_t epoch)
{
  if (epoch > m_epoch)
    *this = At(epoch);
}

Key Direction::SigningKey() const
{
  return DeriveSecpKey(m_chainKey, "ctl-sign");
}

std::string Direction::Pubkey() const
{
  return ToHex(crypto::GetXOnlyPublicKey(SigningKey()));
}

Key Direction::ConversationKey() const
{
  return crypto::HkdfExpandTo<32>(m_chainKey, Label("ctl-enc"));
}

void Ratchet(Contact & contact, int64_t now)
{
  int64_t const oldest = EpochOf(now - kControlGrace);
  contact.m_outgoing.Advance(oldest);
  contact.m_incoming.Advance(oldest);
}

std::string SasDigits(Key const & k1)
{
  auto const b = crypto::HkdfExpandTo<4>(k1, Label("sas"));
  uint32_t const v = (uint32_t{b[0]} << 24 | uint32_t{b[1]} << 16 | uint32_t{b[2]} << 8 | b[3]) % 1000000;
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%03u %03u", v / 1000, v % 1000);
  return buf;
}

// Addressable replacement keeps the event with the higher created_at, and on a tie the one with the
// lower id: created_at must strictly increase per channel or a same-second update may be lost.
nostr::Event ControlEvent(Contact & contact, json::Value const & body, crypto::Rng & rng, int64_t now)
{
  Ratchet(contact, now);
  int64_t const createdAt = std::max(now, contact.m_lastCreatedOut + 1);
  contact.m_lastCreatedOut = createdAt;
  // The stored key can be ahead of the clock if the clock was set back: sign with it rather than fail.
  Direction const d = contact.m_outgoing.At(std::max(EpochOf(createdAt), contact.m_outgoing.Epoch()));
  std::string content = Seal(body, kSizeControl, d.ConversationKey(), rng);
  nostr::Tags tags = {{"d", ""}, {"expiration", std::to_string(EpochEnd(d.Epoch()) + kControlGrace)}};
  return SignEvent(d.SigningKey(), createdAt, kKindStored, std::move(tags), std::move(content), rng);
}

nostr::Event StateEvent(Contact & contact, Relays const & relays, std::optional<Share> const & share, crypto::Rng & rng,
                        int64_t now)
{
  contact.m_seqOut += 1;
  State state;
  state.m_seq = contact.m_seqOut;
  state.m_ts = now;
  state.m_relays = relays;
  state.m_share = share;
  return ControlEvent(contact, ToJson(state), rng, now);
}

std::map<std::string, Direction> IncomingKeys(Contact & contact, int64_t now)
{
  Ratchet(contact, now);
  int64_t const e = EpochOf(now);
  std::map<std::string, Direction> keys;
  for (int64_t epoch = e - 1; epoch <= e + 1; ++epoch)
  {
    if (epoch >= contact.m_incoming.Epoch())
    {
      Direction d = contact.m_incoming.At(epoch);
      keys.emplace(d.Pubkey(), std::move(d));
    }
  }
  return keys;
}

std::optional<State> ReadControl(Contact & contact, nostr::Event const & event, int64_t now)
{
  auto const candidates = IncomingKeys(contact, now);
  std::set<std::string> pubkeys;
  for (auto const & entry : candidates)
    pubkeys.insert(entry.first);
  if (!CheckEvent(event, &pubkeys, kKindStored, "", now))
    return {};
  auto const body = OpenSealed(event.m_content, candidates.at(event.m_pubkey).ConversationKey());
  if (!body)
    return {};
  auto state = ParseState(*body);
  // An older seq is a replay, e.g. a grant re-served after it was ended.
  if (!state || state->m_seq <= contact.m_lastSeqIn)
    return {};
  contact.m_lastSeqIn = state->m_seq;
  contact.m_confirmed = true;
  return state;
}

bool ConfirmationDue(Contact const & contact, int64_t now)
{
  int64_t const e = EpochOf(now);
  return contact.m_joiner && e <= contact.m_pairingEpoch + kConfirmEpochs && EpochOf(contact.m_lastCreatedOut) < e;
}

bool OfferRemoval(Contact const & contact, int64_t now)
{
  return !contact.m_confirmed && now >= EpochEnd(contact.m_pairingEpoch + kConfirmEpochs) + kControlGrace;
}

std::pair<Relays, Relays> SplitRelays(Relays const & named, std::set<std::string> const & trusted)
{
  std::pair<Relays, Relays> out;
  for (auto const & relay : named)
    (trusted.count(relay) != 0 ? out.first : out.second).push_back(relay);
  return out;
}

std::optional<std::string> MissingListeningRelay(Relays const & relays, std::set<std::string> const & trusted)
{
  if (relays.empty() || trusted.count(relays.front()) != 0)
    return {};
  return relays.front();
}

std::vector<std::string> DecoyKeys(ByteSpan decoySeed, int64_t epoch, size_t count)
{
  std::vector<std::string> out;
  for (size_t i = 0; i < count; ++i)
  {
    Bytes const info = WithU32(WithU32(Label("decoy"), static_cast<uint32_t>(epoch)), static_cast<uint32_t>(i));
    Key const prk = crypto::HkdfExpandTo<32>(decoySeed, info);
    out.push_back(ToHex(crypto::GetXOnlyPublicKey(DeriveSecpKey(prk, "decoy-sign"))));
  }
  return out;
}

std::vector<nostr::Filter> InboxFilters(std::vector<ContactPtr> const & contacts, ByteSpan decoySeed, int64_t epoch,
                                        int64_t now)
{
  std::vector<std::string> authors;
  for (auto const & contact : contacts)
    if (contact->m_incoming.Epoch() <= epoch)
      authors.push_back(contact->m_incoming.At(epoch).Pubkey());
  if (authors.empty())
    return {};
  size_t const padded = (authors.size() + kDecoyBlock - 1) / kDecoyBlock * kDecoyBlock;
  for (auto & decoy : DecoyKeys(decoySeed, epoch, padded - authors.size()))
    authors.push_back(std::move(decoy));
  std::sort(authors.begin(), authors.end());

  std::vector<nostr::Filter> filters;
  for (size_t i = 0; i < authors.size(); i += kMaxAuthors)
  {
    std::vector<std::string> const chunk(authors.begin() + i,
                                         authors.begin() + std::min(authors.size(), i + kMaxAuthors));
    filters.push_back({{kKindStored}, chunk, {}, {}});
    filters.push_back({{kKindSignal}, chunk, {}, now - kSignalMaxAge});
  }
  return filters;
}

nostr::Event WatchSignal(Contact & contact, int64_t until, crypto::Rng & rng, int64_t now)
{
  Ratchet(contact, now);
  Direction const d = contact.m_outgoing.At(std::max(EpochOf(now), contact.m_outgoing.Epoch()));
  std::string content = Seal(ToJson(Watch{now, until}), kSizeStream, d.ConversationKey(), rng);
  return SignEvent(d.SigningKey(), now, kKindSignal, {}, std::move(content), rng);
}

std::optional<Watch> ReadSignal(Contact & contact, nostr::Event const & event, int64_t now)
{
  auto const keys = IncomingKeys(contact, now);
  std::set<std::string> pubkeys;
  for (auto const & entry : keys)
    pubkeys.insert(entry.first);
  if (!CheckEvent(event, &pubkeys, kKindSignal, {}, now) || event.m_createdAt < now - kSignalMaxAge)
    return {};
  auto const body = OpenSealed(event.m_content, keys.at(event.m_pubkey).ConversationKey());
  if (!body)
    return {};
  auto watch = ParseWatch(*body);
  if (!watch)
    return {};
  contact.m_confirmed = true;  // only a joiner that finished holds this channel (§6.3)
  return watch;
}
}  // namespace live_location
