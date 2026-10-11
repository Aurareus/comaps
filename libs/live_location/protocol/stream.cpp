#include "live_location/protocol/stream.hpp"

#include "live_location/crypto/schnorr.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"

#include <algorithm>
#include <stdexcept>

namespace live_location
{
Stream Stream::Create(crypto::Rng & rng)
{
  Stream out;
  out.m_secret = RandomSecpKey(rng);
  out.m_key = rng.Get<32>();
  return out;
}

std::string Stream::Pubkey() const
{
  return ToHex(crypto::GetXOnlyPublicKey(m_secret));
}

int64_t Stream::NextCreatedAt(int64_t now)
{
  // Strictly increasing per stream, see ControlEvent().
  m_lastCreated = std::max(now, m_lastCreated + 1);
  return m_lastCreated;
}

nostr::Event Stream::LocationEvent(Location fix, crypto::Rng & rng, int64_t now)
{
  fix.m_seq = ++m_seq;
  int64_t const createdAt = NextCreatedAt(now);
  std::string content = Seal(ToJson(fix), kSizeStream, m_key, rng);
  nostr::Tags tags = {{"d", ""}, {"expiration", std::to_string(createdAt + kTtlLocation)}};
  return SignEvent(m_secret, createdAt, kKindStored, std::move(tags), std::move(content), rng);
}

nostr::Event Stream::EndEvent(crypto::Rng & rng, int64_t now)
{
  int64_t const seq = ++m_seq;
  int64_t const createdAt = NextCreatedAt(now);
  std::string content = Seal(ToJson(StreamEnd{seq, now}), kSizeStream, m_key, rng);
  nostr::Tags tags = {{"d", ""}, {"expiration", std::to_string(createdAt + kTtlLocation)}};
  return SignEvent(m_secret, createdAt, kKindStored, std::move(tags), std::move(content), rng);
}

std::optional<StreamMessage> ReadStream(Share const & grant, nostr::Event const & event, int64_t lastSeq, int64_t now)
{
  std::set<std::string> const author = {grant.m_pk};
  if (!CheckEvent(event, &author, kKindStored, "", now))
    return {};
  auto const body = OpenSealed(event.m_content, grant.m_key);
  if (!body)
    return {};
  auto message = ParseStreamMessage(*body);
  if (!message || SeqOf(*message) <= lastSeq)
    return {};
  return message;
}

Sharer::Sharer(Relays relays) : m_relays(std::move(relays))
{
  if (!IsValidRelayList(m_relays))
    throw std::invalid_argument("invalid relay list");
}

std::optional<int64_t> Sharer::UntilOf(ContactPtr const & contact) const
{
  for (auto const & grant : m_grants)
    if (grant.first == contact)
      return grant.second;
  return {};
}

std::vector<std::pair<ContactPtr, nostr::Event>> Sharer::States(std::vector<ContactPtr> const & removed,
                                                                crypto::Rng & rng, int64_t now)
{
  std::vector<std::pair<ContactPtr, nostr::Event>> out;
  for (auto const & grant : m_grants)
  {
    Share const share{grant.second, m_stream->Pubkey(), m_stream->m_key};
    out.emplace_back(grant.first, StateEvent(*grant.first, m_relays, share, rng, now));
  }
  for (auto const & contact : removed)
    out.emplace_back(contact, StateEvent(*contact, m_relays, std::nullopt, rng, now));
  Shuffle(out, rng);
  return out;
}

Rekey Sharer::Start(Grants grants, crypto::Rng & rng, int64_t now)
{
  if (m_stream)
    throw std::logic_error("already sharing");
  m_grants = std::move(grants);
  m_stream = Stream::Create(rng);
  m_streamEpoch = EpochOf(now);
  m_notBefore = now;
  Rekey out;
  out.m_states = States({}, rng, now);
  return out;
}

Rekey Sharer::Change(Grants grants, crypto::Rng & rng, int64_t now)
{
  if (grants.empty())
    return Stop(rng, now);
  std::vector<ContactPtr> removed;
  for (auto const & old : m_grants)
  {
    bool const kept = std::any_of(grants.begin(), grants.end(), [&](auto const & g) { return g.first == old.first; });
    if (!kept)
      removed.push_back(old.first);
  }
  Stream old = std::move(*m_stream);
  m_grants = std::move(grants);
  m_stream = Stream::Create(rng);
  m_streamEpoch = EpochOf(now);
  Rekey out;
  out.m_states = States(removed, rng, now);
  out.m_end = old.EndEvent(rng, now);
  m_notBefore = now + kRekeyDelayMin + RandomBelow(rng, static_cast<uint32_t>(kRekeyDelayMax - kRekeyDelayMin + 1));
  return out;
}

nostr::Event Sharer::Extend(ContactPtr const & contact, int64_t until, crypto::Rng & rng, int64_t now)
{
  if (!UntilOf(contact))
    throw std::invalid_argument("not a current recipient: use Change()");
  if (!(until == 0 || until > now))
    throw std::invalid_argument("until in the past: use Change()");
  for (auto & grant : m_grants)
    if (grant.first == contact)
      grant.second = until;
  return CurrentState(contact, rng, now);
}

nostr::Event Sharer::CurrentState(ContactPtr const & contact, crypto::Rng & rng, int64_t now)
{
  std::optional<Share> share;
  if (auto const until = UntilOf(contact))
    share = Share{*until, m_stream->Pubkey(), m_stream->m_key};
  return StateEvent(*contact, m_relays, share, rng, now);
}

Rekey Sharer::Stop(crypto::Rng & rng, int64_t now)
{
  if (!m_stream)
    throw std::logic_error("not sharing");
  std::vector<ContactPtr> removed;
  for (auto const & grant : m_grants)
    removed.push_back(grant.first);
  m_grants.clear();
  Rekey out;
  out.m_states = States(removed, rng, now);
  out.m_end = m_stream->EndEvent(rng, now);
  m_stream.reset();
  return out;
}

std::optional<Rekey> Sharer::Tick(crypto::Rng & rng, int64_t now)
{
  if (!m_stream)
    return {};
  Grants current;
  for (auto const & grant : m_grants)
    if (grant.second == 0 || grant.second > now)
      current.push_back(grant);
  if (current.size() != m_grants.size() || EpochOf(now) != m_streamEpoch)
    return Change(std::move(current), rng, now);
  return {};
}

std::optional<nostr::Event> Sharer::PublishLocation(Location const & fix, crypto::Rng & rng, int64_t now)
{
  if (!m_stream || now < m_notBefore)
    return {};
  return m_stream->LocationEvent(fix, rng, now);
}

void Following::OnState(State const & state, int64_t now)
{
  auto const & share = state.m_share;
  if (!share || (share->m_until != 0 && share->m_until <= now))
  {
    Stop();
  }
  else if (!m_grant || share->m_pk != m_grant->m_pk)
  {
    // A new stream. The old position stays, stale, until its first location.
    m_grant = share;
    m_lastSeq = 0;
    m_endedAt.reset();
    m_stale = m_position.has_value();
  }
  else
  {
    m_grant = share;  // e.g. a new until
  }
}

std::optional<StreamMessage> Following::OnStream(nostr::Event const & event, int64_t now)
{
  if (!m_grant)
    return {};
  if (m_grant->m_until != 0 && m_grant->m_until <= now)
  {
    Stop();
    return {};
  }
  auto message = ReadStream(*m_grant, event, m_lastSeq, now);
  if (!message)
    return {};
  m_lastSeq = SeqOf(*message);
  if (std::holds_alternative<StreamEnd>(*message))
  {
    m_grant.reset();  // erase the stream key
    m_lastSeq = 0;
    m_stale = m_position.has_value();
    m_endedAt = now;
  }
  else
  {
    m_position = std::get<Location>(*message);
    m_stale = false;
  }
  return message;
}

void Following::Tick(int64_t now)
{
  if (!m_grant && m_endedAt && now >= *m_endedAt + kEndGrace)
    Stop();
}

void Following::Stop()
{
  m_grant.reset();
  m_lastSeq = 0;
  m_position.reset();
  m_stale = false;
  m_endedAt.reset();
}
}  // namespace live_location
