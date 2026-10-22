#include "live_location/manager/manager.hpp"

#include "live_location/encoding/binary.hpp"
#include "live_location/manager/marks.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/json.hpp"
#include "live_location/protocol/persist.hpp"

#include "base/logging.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace live_location
{
namespace
{
// Stores of other versions are not read, like stores that cannot be read: the app offers to delete them.
// While the feature is in development each change of the format takes the next number; it goes back to 1
// for the first release.
uint8_t constexpr kStateVersion = 5;
int64_t constexpr kQrLifetime = 600;      // design doc §11.2
int64_t constexpr kLinkLifetime = 86400;  // spec §6.1: at most a day
int64_t constexpr kCatchUpMs = 30'000;    // how long the previous epoch's states are read for
int64_t constexpr kPairingRetryMs = 30'000;
size_t constexpr kMaxPreviousRelays = 8;  // after several changes before everyone moved
int64_t constexpr kMoveEpochs = 30;       // the previous home relays are read at most through epoch e_c + 30

bool Contains(Relays const & relays, std::string const & url)
{
  return std::find(relays.begin(), relays.end(), url) != relays.end();
}

double DistanceM(Location const & a, Location const & b)
{
  double constexpr kEarthRadiusM = 6'371'000;
  double constexpr kRad = 3.14159265358979323846 / 180;
  double const dLat = (b.m_lat - a.m_lat) * kRad;
  double const dLon = (b.m_lon - a.m_lon) * kRad;
  double const h = std::sin(dLat / 2) * std::sin(dLat / 2) +
                   std::cos(a.m_lat * kRad) * std::cos(b.m_lat * kRad) * std::sin(dLon / 2) * std::sin(dLon / 2);
  return 2 * kEarthRadiusM * std::asin(std::min(1.0, std::sqrt(h)));
}

// A provider's fix as receivers accept it (spec §9): without a usable time, position or accuracy,
// nothing; an optional field out of range is left out.
std::optional<Location> Checked(Location fix)
{
  using json::IsFinite;
  if (fix.m_ts < 0 || fix.m_ts > kMaxJsonInt || !IsFinite(fix.m_lat) || !IsFinite(fix.m_lon) || !IsFinite(fix.m_acc) ||
      std::abs(fix.m_lat) > 90 || std::abs(fix.m_lon) > 180 || fix.m_acc < 0)
  {
    return {};
  }
  if (fix.m_spd && (!IsFinite(*fix.m_spd) || *fix.m_spd < 0))
    fix.m_spd.reset();
  if (fix.m_brg && (!IsFinite(*fix.m_brg) || *fix.m_brg < 0 || *fix.m_brg >= 360))
    fix.m_brg.reset();
  if (fix.m_alt && !IsFinite(*fix.m_alt))
    fix.m_alt.reset();
  return fix;
}
}  // namespace

struct Manager::Peer
{
  std::string m_id;
  ContactPtr m_contact;
  bool m_hidden = false;
  // Since this user's home relays last changed, nothing from the contact has come through the new ones
  // (spec §11): it may still send to the previous ones.
  bool m_notMoved = false;
  // The contact's relays as of the last state of this user's that one of them accepted: a state naming
  // others is answered there (spec §11).
  Relays m_deliveredTo;
  bool m_answering = false;  // in memory: an answer waits for its OK
  std::string m_color;       // the dot colour the contact chose, from its last state; "" if none
  // The viewer's side of the contact's share, in memory only.
  Following m_following;
  int64_t m_streamEpoch = 0;  // of the grant: the stream travels in that epoch's scope
  relay::RelayPool::SubscriptionId m_stream = 0;
  std::string m_streamPk;
  Relays m_streamRelays;
};

struct Manager::Session
{
  std::string m_id;
  bool m_byLink = false;
  std::unique_ptr<Inviter> m_inviter;
  std::unique_ptr<Joiner> m_joiner;
  PairingInfo::Stage m_stage = PairingInfo::Stage::Waiting;
  bool m_codeConfirmed = false;  // the joiner's user tapped "Codes match"
  std::string m_peerName;
  std::string m_sas;
  std::string m_contactId;
  relay::RelayPool::SubscriptionId m_subscription = 0;
  std::vector<nostr::Event> m_held;    // out of order: offered again after the next step
  std::vector<nostr::Event> m_unsent;  // steps no relay has accepted yet

  Invite const & GetInvite() const { return m_inviter ? m_inviter->GetInvite() : m_joiner->GetInvite(); }
  bool Watching() const { return m_inviter ? !m_inviter->IsAborted() : !m_joiner->IsAborted(); }
};

Manager::Manager(Executor & executor, relay::Transport & transport, store::Store & store, crypto::Rng & rng,
                 ManagerListener & listener, ManagerConfig config)
  : m_executor(executor)
  , m_store(store)
  , m_rng(rng)
  , m_listener(listener)
  , m_config(config)
{
  m_pool = std::make_unique<relay::RelayPool>(transport, executor, rng,
                                              [this](std::string const & url) { return IsAllowed(url); });
  m_pool->OnEchoed([this](std::string const & url) { OnEchoed(url); });
  Fresh();
}

Manager::~Manager()
{
  m_pool.reset();
  Cancel(m_heartbeat);
  Cancel(m_streamStart);
  Cancel(m_clock);
  Cancel(m_watchTimer);
  Cancel(m_viewTimer);
}

// --- Store ----------------------------------------------------------------------------------

void Manager::Fresh()
{
  m_settings = Settings();
  m_settings.m_homeRelays.assign(kDefaultRelays.begin(), kDefaultRelays.end());
  m_decoySeed = m_rng.Get<32>();
  m_echoed.clear();
  m_peers.clear();
  m_sessions.clear();
  m_sharer.reset();
  m_resumable.clear();
}

SecretBytes Manager::Encode(std::set<ByteArray<32>> & digests) const
{
  binary::Writer writer;
  writer.U8(kStateVersion);
  writer.Secret(m_decoySeed);

  writer.String(m_settings.m_name);
  writer.String(m_settings.m_color);
  persist::WriteRelays(writer, m_settings.m_homeRelays);
  writer.U32(static_cast<uint32_t>(m_settings.m_previousRelays.size()));
  for (auto const & url : m_settings.m_previousRelays)
    writer.String(url);
  writer.I64(m_settings.m_relaysChanged);
  writer.U32(static_cast<uint32_t>(m_settings.m_approved.size()));
  for (auto const & [url, contact] : m_settings.m_approved)
  {
    writer.String(url);
    writer.String(contact);
  }
  writer.U32(static_cast<uint32_t>(m_settings.m_declined.size()));
  for (auto const & [url, contact] : m_settings.m_declined)
  {
    writer.String(url);
    writer.String(contact);
  }
  writer.Bool(m_settings.m_requestLive);
  writer.Bool(m_settings.m_allowLive);
  writer.U8(static_cast<uint8_t>(std::clamp(m_settings.m_lowBatteryStop, 0, 100)));
  // The echo record, of the relays still in use.
  std::vector<std::string> echoed;
  for (auto const & url : m_echoed)
    if (Contains(m_settings.m_homeRelays, url) || Contains(m_settings.m_previousRelays, url))
      echoed.push_back(url);
  writer.U32(static_cast<uint32_t>(echoed.size()));
  for (auto const & url : echoed)
    writer.String(url);

  writer.U32(static_cast<uint32_t>(m_peers.size()));
  for (auto const & peer : m_peers)
  {
    writer.String(peer->m_id);
    persist::WriteContact(writer, *peer->m_contact);
    writer.Bool(peer->m_hidden);
    writer.Bool(peer->m_notMoved);
    persist::WriteRelays(writer, peer->m_deliveredTo);
    writer.String(peer->m_color);
  }

  auto const idOf = [this](ContactPtr const & contact)
  {
    for (auto const & peer : m_peers)
      if (peer->m_contact == contact)
        return peer->m_id;
    return std::string();
  };
  writer.U32(static_cast<uint32_t>(m_sessions.size()));
  for (auto const & session : m_sessions)
  {
    writer.String(session->m_id);
    writer.Bool(session->m_byLink);
    writer.Bool(session->m_inviter != nullptr);
    writer.U8(static_cast<uint8_t>(session->m_stage));
    writer.Bool(session->m_codeConfirmed);
    writer.String(session->m_peerName);
    writer.String(session->m_sas);
    writer.String(session->m_contactId);
    if (session->m_inviter)
      session->m_inviter->Save(writer, idOf);
    else
      session->m_joiner->Save(writer, idOf);
  }

  // The share's recipients, so that the app can offer to resume it after its process died.
  Recipients share = m_resumable;
  if (m_sharer && m_sharer->IsSharing())
  {
    share.clear();
    for (auto const & [contact, until] : m_sharer->GetGrants())
      share.emplace_back(idOf(contact), until);
  }
  writer.U32(static_cast<uint32_t>(share.size()));
  for (auto const & [id, until] : share)
  {
    writer.String(id);
    writer.I64(until);
  }

  SecretBytes out = writer.Finish();
  digests = writer.SecretDigests();
  return out;
}

void Manager::Decode(ByteSpan data)
{
  binary::Reader reader(data);
  if (reader.U8() != kStateVersion)
    throw binary::FormatError("store version");
  m_decoySeed = reader.Secret();

  m_settings = Settings();
  m_settings.m_name = reader.String();
  m_settings.m_color = reader.String();
  if (!m_settings.m_color.empty() && !DotColorRgba(m_settings.m_color))
    throw binary::FormatError("colour");
  m_settings.m_homeRelays = persist::ReadRelays(reader);
  for (uint32_t i = 0, n = reader.Count(4); i < n; ++i)
  {
    std::string url = reader.String();
    if (!IsValidRelayUrl(url))
      throw binary::FormatError("relay");
    m_settings.m_previousRelays.push_back(std::move(url));
  }
  m_settings.m_relaysChanged = reader.I64();
  for (uint32_t i = 0, n = reader.Count(8); i < n; ++i)
  {
    std::string url = reader.String();
    m_settings.m_approved[url] = reader.String();
  }
  for (uint32_t i = 0, n = reader.Count(8); i < n; ++i)
  {
    std::string url = reader.String();
    m_settings.m_declined[url] = reader.String();
  }
  m_settings.m_requestLive = reader.Bool();
  m_settings.m_allowLive = reader.Bool();
  m_settings.m_lowBatteryStop = reader.U8();
  m_echoed.clear();
  for (uint32_t i = 0, n = reader.Count(4); i < n; ++i)
    m_echoed.insert(reader.String());

  m_peers.clear();
  for (uint32_t i = 0, n = reader.Count(8); i < n; ++i)
  {
    auto peer = std::make_unique<Peer>();
    peer->m_id = reader.String();
    peer->m_contact = persist::ReadContact(reader);
    peer->m_hidden = reader.Bool();
    peer->m_notMoved = reader.Bool();
    peer->m_deliveredTo = persist::ReadRelays(reader);
    peer->m_color = reader.String();
    m_peers.push_back(std::move(peer));
  }

  auto const contactById = [this](std::string const & id)
  {
    Peer * peer = FindPeer(id);
    return peer != nullptr ? peer->m_contact : nullptr;
  };
  m_sessions.clear();
  for (uint32_t i = 0, n = reader.Count(8); i < n; ++i)
  {
    auto session = std::make_unique<Session>();
    session->m_id = reader.String();
    session->m_byLink = reader.Bool();
    bool const inviter = reader.Bool();
    uint8_t const stage = reader.U8();
    if (stage > static_cast<uint8_t>(PairingInfo::Stage::Expired))
      throw binary::FormatError("pairing stage");
    session->m_stage = static_cast<PairingInfo::Stage>(stage);
    session->m_codeConfirmed = reader.Bool();
    session->m_peerName = reader.String();
    session->m_sas = reader.String();
    session->m_contactId = reader.String();
    if (inviter)
      session->m_inviter = Inviter::Load(reader, contactById);
    else
      session->m_joiner = Joiner::Load(reader, contactById);
    m_sessions.push_back(std::move(session));
  }

  m_resumable.clear();
  for (uint32_t i = 0, n = reader.Count(12); i < n; ++i)
  {
    std::string id = reader.String();
    int64_t const until = reader.I64();
    if (FindPeer(id) != nullptr)
      m_resumable.emplace_back(std::move(id), until);
  }
  if (!reader.AtEnd())
    throw binary::FormatError("trailing data");
}

void Manager::Save()
{
  // Nothing is written before the store was read, or the user chose to delete it: a store that could
  // not be read (a key store failing for a while, a file that could not be opened) stays as it is.
  if (!m_started)
    return;
  std::set<ByteArray<32>> digests;
  SecretBytes const contents = Encode(digests);
  // A failed write is no store error: the data is still the user's, and the next change writes it all. The
  // app is told when writing starts to fail.
  if (m_store.Save(contents, digests))
  {
    m_writeFailing = false;
    return;
  }
  LOG(LWARNING, ("Live location: could not write the store"));
  if (!std::exchange(m_writeFailing, true))
    m_listener.OnWriteFailed();
}

bool Manager::Start()
{
  SecretBytes contents;
  switch (m_store.Load(contents))
  {
  case store::Store::Result::Empty: Fresh(); break;
  case store::Store::Result::Unreadable:
  case store::Store::Result::Unavailable: m_listener.OnStoreError(); return false;
  case store::Store::Result::Loaded:
    try
    {
      Decode(contents);
    }
    catch (binary::FormatError const & e)
    {
      LOG(LWARNING, ("Live location: the store cannot be decoded:", e.what()));
      Fresh();
      m_listener.OnStoreError();
      return false;
    }
    {
      std::set<ByteArray<32>> digests;
      Encode(digests);
      m_store.SetBaseline(std::move(digests));
    }
    break;
  }
  m_started = true;
  // The echo check judges a relay that has ever sent an event back, also one that stopped before this run
  // (spec §11).
  m_pool->SetEchoing(m_echoed);
  OnClock();  // erases what is due after the time the app was closed, and expires invites
  NotifyContacts();
  NotifySharing();
  return true;
}

void Manager::DeleteAllData()
{
  m_pool->CloseAll();
  m_inbox = 0;
  m_oldInbox = 0;
  m_catchUp = 0;
  m_inboxAuthors.clear();
  Cancel(m_heartbeat);
  Cancel(m_streamStart);
  Cancel(m_watchTimer);
  Cancel(m_viewTimer);
  m_store.Erase();
  Fresh();
  m_started = true;  // also after a store that could not be read
  m_lastFix.reset();
  m_lastPublished.reset();
  m_liveUntil = 0;
  m_asked.clear();
  Save();
  UpdateLocationRequest();
  ScheduleClock();
  NotifyContacts();
  NotifyPositions();
  NotifySharing();
}

// --- Helpers --------------------------------------------------------------------------------

std::string Manager::NewId()
{
  return ToHex(m_rng.GetBytes(8));
}

Manager::Peer * Manager::FindPeer(std::string const & id)
{
  for (auto & peer : m_peers)
    if (peer->m_id == id)
      return peer.get();
  return nullptr;
}

Manager::Peer * Manager::FindPeer(ContactPtr const & contact)
{
  for (auto & peer : m_peers)
    if (peer->m_contact == contact)
      return peer.get();
  return nullptr;
}

Manager::Session * Manager::FindSession(std::string const & id)
{
  for (auto & session : m_sessions)
    if (session->m_id == id)
      return session.get();
  return nullptr;
}

bool Manager::MoveWindow() const
{
  return m_settings.m_relaysChanged != 0 && EpochOf(Now()) <= m_settings.m_relaysChanged + kMoveEpochs;
}

bool Manager::MovePending() const
{
  if (!MoveWindow())
    return false;
  // A contact that never finished connecting (offered for removal) will not move: it does not count.
  int64_t const now = Now();
  for (auto const & peer : m_peers)
    if (peer->m_notMoved && !OfferRemoval(*peer->m_contact, now))
      return true;
  return false;
}

std::optional<std::string> Manager::Color() const
{
  if (m_settings.m_color.empty())
    return {};
  return m_settings.m_color;
}

void Manager::OnEchoed(std::string const & url)
{
  if (m_echoed.insert(url).second)
    Save();
}

Relays Manager::OldRelays() const
{
  Relays relays;
  if (MovePending())
    for (auto const & url : m_settings.m_previousRelays)
      if (std::find(m_settings.m_homeRelays.begin(), m_settings.m_homeRelays.end(), url) ==
          m_settings.m_homeRelays.end())
        relays.push_back(url);
  return relays;
}

std::set<std::string> Manager::Trusted() const
{
  std::set<std::string> trusted(m_settings.m_homeRelays.begin(), m_settings.m_homeRelays.end());
  if (MovePending())
    trusted.insert(m_settings.m_previousRelays.begin(), m_settings.m_previousRelays.end());
  trusted.insert(kDefaultRelays.begin(), kDefaultRelays.end());
  for (auto const & approved : m_settings.m_approved)
    trusted.insert(approved.first);
  return trusted;
}

bool Manager::IsAllowed(std::string const & url) const
{
  return Trusted().count(url) != 0;
}

Relays Manager::Allowed(Relays const & relays) const
{
  return SplitRelays(relays, Trusted()).first;
}

void Manager::AskConsent(std::string const & url, std::string const & contactName, ConsentRequest::Purpose purpose)
{
  if (IsAllowed(url) || m_settings.m_declined.count(url) != 0 || !m_asked.insert(url).second)
    return;
  ConsentRequest request;
  request.m_url = url;
  request.m_contactName = contactName;
  request.m_purpose = purpose;
  m_listener.OnConsentNeeded(request);
}

Executor::TaskId Manager::Later(int64_t delayMs, std::function<void()> task)
{
  std::weak_ptr<int> alive = m_alive;
  return m_executor.PostDelayed(std::max<int64_t>(0, delayMs), [alive, task = std::move(task)]
  {
    if (!alive.expired())
      task();
  });
}

void Manager::Cancel(Executor::TaskId & id)
{
  if (id != Executor::kNoTask)
    m_executor.Cancel(id);
  id = Executor::kNoTask;
}

// --- Settings -------------------------------------------------------------------------------

void Manager::SetForeground(bool foreground)
{
  if (m_foreground == foreground)
    return;
  m_foreground = foreground;
  if (foreground)
  {
    SendConfirmations();
    SendWatchSignals();
  }
  UpdateConnections();
}

bool Manager::SetName(std::string name)
{
  if (!m_started || !IsValidName(name))
    return false;
  m_settings.m_name = std::move(name);
  Save();
  return true;
}

bool Manager::SetHomeRelays(Relays relays)
{
  if (!m_started || !IsValidRelayList(relays))
    return false;
  if (relays == m_settings.m_homeRelays)
    return true;
  if (m_peers.empty() && m_sessions.empty())
  {
    // Nobody to tell, and nobody who sends to the old relays.
    m_settings.m_homeRelays = std::move(relays);
    m_settings.m_previousRelays.clear();
    m_settings.m_relaysChanged = 0;
    Save();
    UpdateConnections();
    return true;
  }
  // Contacts still send to the previous relays until they learn the new list: they are read until
  // everyone has moved, together with those of an earlier change that not everyone had followed yet.
  Relays previous = m_settings.m_homeRelays;
  if (MovePending())
    for (auto const & url : m_settings.m_previousRelays)
      if (std::find(previous.begin(), previous.end(), url) == previous.end())
        previous.push_back(url);
  previous.erase(std::remove_if(previous.begin(), previous.end(), [&](std::string const & url)
  { return std::find(relays.begin(), relays.end(), url) != relays.end(); }),
                 previous.end());
  if (previous.size() > kMaxPreviousRelays)
    previous.resize(kMaxPreviousRelays);
  m_settings.m_previousRelays = std::move(previous);
  m_settings.m_relaysChanged = EpochOf(Now());
  m_settings.m_homeRelays = std::move(relays);
  for (auto & peer : m_peers)
    peer->m_notMoved = true;  // until something of theirs comes through the new relays
  AnnounceRelays();
  UpdateConnections();
  NotifyContacts();
  return true;
}

void Manager::AnnounceRelays()
{
  // Every contact gets a state naming the new list. A running share is re-keyed, so that its grants,
  // its stream and its listening relay move too. All the states leave in one shuffled batch: their
  // order must not tell the relays who receives the share.
  int64_t const now = Now();
  Rekey rekey;
  int64_t oldEpoch = 0;
  Relays const oldRelays = m_shareRelays;
  bool const sharing = m_sharer && m_sharer->IsSharing();
  std::set<ContactPtr> granted;
  if (sharing)
  {
    oldEpoch = m_sharer->StreamEpoch();
    m_shareRelays = m_settings.m_homeRelays;
    m_sharer->SetRelays(m_shareRelays);
    rekey = m_sharer->Change(m_sharer->GetGrants(), m_rng, now);
    for (auto const & grant : m_sharer->GetGrants())
      granted.insert(grant.first);
    m_lastPublished.reset();
  }
  for (auto const & peer : m_peers)
    if (granted.count(peer->m_contact) == 0)
      rekey.m_states.emplace_back(
          peer->m_contact, StateEvent(*peer->m_contact, m_settings.m_homeRelays, std::nullopt, m_rng, now, Color()));
  Shuffle(rekey.m_states, m_rng);
  Save();  // the seqs and created_at of these states, and the new stream, before they leave
  PublishRekey(std::move(rekey), oldEpoch, oldRelays);
  if (sharing)
  {
    ScheduleStreamStart();
    ScheduleClock();
    NotifySharing();
  }
}

void Manager::SetConsent(std::string const & url, Consent consent, std::string const & forContact)
{
  if (!m_started)
    return;
  switch (consent)
  {
  case Consent::Allow:
    m_settings.m_approved[url] = forContact;
    m_settings.m_declined.erase(url);
    break;
  case Consent::NotNow:
    // Kept for this run only: asked again the next time the relay is needed in another one.
    m_asked.insert(url);
    NotifyContacts();
    return;
  case Consent::Refuse:
    m_settings.m_declined[url] = forContact;
    m_settings.m_approved.erase(url);
    break;
  }
  Save();
  if (consent == Consent::Allow)
    for (auto & peer : m_peers)
      Answer(*peer);  // the relay a contact moved to, now allowed
  UpdateConnections();
  NotifyContacts();
}

bool Manager::SetColor(std::string color)
{
  if (!m_started || (!color.empty() && !DotColorRgba(color)))
    return false;
  if (color == m_settings.m_color)
    return true;
  m_settings.m_color = std::move(color);
  // Viewers learn it from the next state; the current recipients, who see the dot, get theirs now.
  std::vector<std::pair<ContactPtr, nostr::Event>> states;
  if (m_sharer)
  {
    m_sharer->SetColor(Color());
    if (m_sharer->IsSharing())
      for (auto const & grant : m_sharer->GetGrants())
        states.emplace_back(grant.first, m_sharer->CurrentState(grant.first, m_rng, Now()));
    Shuffle(states, m_rng);
  }
  Save();
  for (auto const & [contact, event] : states)
    PublishControl(contact, event);
  return true;
}

bool Manager::SetLowBatteryStop(int percent)
{
  if (!m_started || percent < 0 || percent > 50)
    return false;
  if (percent == m_settings.m_lowBatteryStop)
    return true;  // picked again: a share started at or below it runs on
  m_settings.m_lowBatteryStop = percent;
  Save();
  m_batteryArmed = true;  // a level chosen while sharing applies at once
  if (m_battery >= 0)
    OnBatteryLevel(m_battery, m_charging);
  return true;
}

void Manager::RevokeConsent(std::string const & url)
{
  if (!m_started)
    return;
  m_settings.m_approved.erase(url);
  m_settings.m_declined.erase(url);
  m_asked.erase(url);
  Save();
  UpdateConnections();
  NotifyContacts();
}

void Manager::SetRequestLive(bool request)
{
  if (!m_started)
    return;
  m_settings.m_requestLive = request;
  Save();
  UpdateConnections();
  NotifyContacts();
}

void Manager::SetAllowLive(bool allow)
{
  if (!m_started)
    return;
  m_settings.m_allowLive = allow;
  if (!allow)
    m_liveUntil = 0;
  Save();
  UpdateLocationRequest();
  NotifySharing();
}

// --- Pairing --------------------------------------------------------------------------------

PairingInfo Manager::Info(Session const & session) const
{
  PairingInfo info;
  info.m_id = session.m_id;
  info.m_inviter = session.m_inviter != nullptr;
  info.m_byLink = session.m_byLink;
  info.m_stage = session.m_stage;
  info.m_expiresAt = session.GetInvite().m_expiresAt;
  if (session.m_inviter && session.GetInvite().m_psk && session.m_stage == PairingInfo::Stage::Waiting)
    info.m_link = session.GetInvite().Link();
  info.m_sas = session.m_sas;
  info.m_peerName = session.m_peerName;
  info.m_contactId = session.m_contactId;
  return info;
}

std::optional<PairingInfo> Manager::CreateInvite(bool byLink)
{
  if (!m_started || !IsValidName(m_settings.m_name))
    return {};
  auto session = std::make_unique<Session>();
  session->m_id = NewId();
  session->m_byLink = byLink;
  session->m_inviter =
      std::make_unique<Inviter>(m_settings.m_homeRelays, m_rng, Now(), byLink ? kLinkLifetime : kQrLifetime);
  Session & s = *session;
  m_sessions.push_back(std::move(session));
  Save();
  ScheduleClock();
  UpdateConnections();
  PairingInfo const info = Info(s);
  m_listener.OnPairing(info);
  return info;
}

std::optional<PairingInfo> Manager::OpenInvite(std::string const & link)
{
  if (!m_started || !IsValidName(m_settings.m_name))
    return {};
  auto const invite = Invite::FromLink(link);
  if (!invite)
    return {};
  PairingInfo info;
  info.m_expiresAt = invite->m_expiresAt;
  for (auto const & session : m_sessions)
    if (session->m_joiner && session->GetInvite().m_ipk == invite->m_ipk)
      return Info(*session);  // opened twice

  // Relay consent: the invite's relays learn this phone's address while it pairs (spec §11).
  for (auto const & url : invite->m_relays)
    if (!IsAllowed(url) && m_settings.m_declined.count(url) == 0 && m_asked.count(url) == 0)
      info.m_needsConsent.push_back(url);
  if (!info.m_needsConsent.empty())
  {
    info.m_stage = PairingInfo::Stage::NeedsConsent;
    return info;
  }
  if (Allowed(invite->m_relays).empty())
  {
    // Each of its relays was refused, or put off in this run: the app says which, and may allow one.
    info.m_needsConsent = invite->m_relays;
    info.m_stage = PairingInfo::Stage::Cancelled;
    return info;
  }

  std::unique_ptr<Joiner> joiner;
  try
  {
    joiner = std::make_unique<Joiner>(*invite, m_settings.m_name, m_settings.m_homeRelays, m_rng, Now());
  }
  catch (std::invalid_argument const &)
  {
    info.m_stage = PairingInfo::Stage::Expired;  // or a lifetime over a day, which only an attacker makes
    return info;
  }
  auto session = std::make_unique<Session>();
  session->m_id = NewId();
  session->m_byLink = true;
  session->m_joiner = std::move(joiner);
  std::string const id = session->m_id;
  nostr::Event const step0 = session->m_joiner->CommitEvent(m_rng, Now());
  m_sessions.push_back(std::move(session));
  Save();
  PublishPairing(id, step0);
  ScheduleClock();
  UpdateConnections();
  info = Info(*FindSession(id));
  m_listener.OnPairing(info);
  return info;
}

void Manager::PublishPairing(std::string const & sessionId, nostr::Event const & event)
{
  Session * session = FindSession(sessionId);
  if (session == nullptr)
    return;
  auto & unsent = session->m_unsent;
  if (std::none_of(unsent.begin(), unsent.end(), [&](auto const & e) { return e.m_id == event.m_id; }))
    unsent.push_back(event);
  std::string const eventId = event.m_id;
  m_pool->Publish(relay::PairingScope(sessionId), Allowed(session->GetInvite().m_relays), event,
                  [this, sessionId, eventId](bool delivered)
  {
    Session * s = FindSession(sessionId);
    if (s == nullptr)
      return;
    if (delivered)
    {
      std::erase_if(s->m_unsent, [&](auto const & e) { return e.m_id == eventId; });
      return;
    }
    // Relays keep one event per step and author, so sending a step again is harmless. Only while the
    // app is in the foreground: in the background nothing connects for a pairing.
    Later(kPairingRetryMs, [this, sessionId, eventId]
    {
      Session * again = FindSession(sessionId);
      if (again == nullptr || !m_foreground || Now() >= again->GetInvite().m_expiresAt)
        return;
      for (auto const & e : again->m_unsent)
      {
        if (e.m_id == eventId)
        {
          nostr::Event const copy = e;
          PublishPairing(sessionId, copy);
          return;
        }
      }
    });
  });
}

void Manager::OnPairingEvent(std::string const & sessionId, nostr::Event const & event)
{
  Session * session = FindSession(sessionId);
  if (session == nullptr)
    return;
  std::optional<Outcome> outcome;
  try
  {
    outcome = session->m_inviter ? session->m_inviter->OnEvent(event, m_rng, Now())
                                 : session->m_joiner->OnEvent(event, m_rng, Now());
  }
  catch (PairingOutOfOrder const &)
  {
    session->m_held.push_back(event);
    return;
  }
  catch (PairingAborted const & e)
  {
    LOG(LINFO, ("Live location: pairing stopped:", e.what()));
    EndSession(sessionId, PairingInfo::Stage::Conflict);
    return;
  }
  if (!outcome)
    return;
  HandleOutcome(*session, *outcome);

  // A step held back may be due now.
  session = FindSession(sessionId);
  if (session != nullptr && !session->m_held.empty())
  {
    std::vector<nostr::Event> held = std::move(session->m_held);
    session->m_held.clear();
    for (auto const & e : held)
      OnPairingEvent(sessionId, e);
  }
}

Manager::Peer & Manager::AddPeer(ContactPtr const & contact)
{
  auto peer = std::make_unique<Peer>();
  peer->m_id = NewId();
  peer->m_contact = contact;
  peer->m_deliveredTo = contact->m_relays;  // the pairing named them: nothing to answer
  Peer & out = *peer;
  m_peers.push_back(std::move(peer));
  return out;
}

void Manager::HandleOutcome(Session & session, Outcome const & outcome)
{
  if (outcome.m_contact && session.m_joiner)
  {
    // The joiner accepted step 3: a new contact, and its first confirmation on the new channel.
    Peer & peer = AddPeer(outcome.m_contact);
    peer.m_contact->m_verified = session.m_codeConfirmed;
    session.m_stage = PairingInfo::Stage::Connected;
    session.m_peerName = outcome.m_contact->m_name;
    session.m_contactId = peer.m_id;
    Save();
    if (outcome.m_publish)
      PublishControl(outcome.m_contact, *outcome.m_publish);
    UpdateConnections();
    NotifyContacts();
    m_listener.OnPairing(Info(session));
    return;
  }
  if (outcome.m_declined)
  {
    EndSession(session.m_id, PairingInfo::Stage::Declined);
    return;
  }
  if (outcome.m_publish)
    PublishPairing(session.m_id, *outcome.m_publish);
  if (outcome.m_showCode)
  {
    session.m_stage = PairingInfo::Stage::CompareCode;
    session.m_sas = outcome.m_showCode->m_sas;
    if (outcome.m_showCode->m_name)
      session.m_peerName = *outcome.m_showCode->m_name;
  }
  Save();
  if (outcome.m_flagged)
    NotifyContacts();
  m_listener.OnPairing(Info(session));
}

void Manager::EndSession(std::string const & sessionId, PairingInfo::Stage stage, bool notify)
{
  auto const it =
      std::find_if(m_sessions.begin(), m_sessions.end(), [&](auto const & s) { return s->m_id == sessionId; });
  if (it == m_sessions.end())
    return;
  std::unique_ptr<Session> session = std::move(*it);
  m_sessions.erase(it);
  if (session->m_inviter)
    session->m_inviter->Abort();
  else
    session->m_joiner->Abort();
  if (session->m_subscription != 0)
    m_pool->Unsubscribe(session->m_subscription);
  session->m_stage = stage;
  Save();  // the pairing's secrets are gone: this rotates the store's keys
  ScheduleClock();
  if (notify)
    m_listener.OnPairing(Info(*session));
}

void Manager::ConfirmCode(std::string const & pairingId, bool match)
{
  Session * session = FindSession(pairingId);
  if (session == nullptr || !session->m_joiner)
    return;
  if (!match)
  {
    EndSession(pairingId, PairingInfo::Stage::Cancelled);
    return;
  }
  session->m_codeConfirmed = true;
  if (Peer * peer = FindPeer(session->m_contactId))
  {
    peer->m_contact->m_verified = true;
    NotifyContacts();
  }
  Save();
}

void Manager::Decide(std::string const & pairingId, bool accept, bool compared)
{
  Session * session = FindSession(pairingId);
  if (session == nullptr || !session->m_inviter)
    return;
  Outcome outcome;
  try
  {
    outcome = session->m_inviter->Decide(accept, m_settings.m_name, m_settings.m_homeRelays, m_rng, Now());
  }
  catch (std::exception const & e)
  {
    LOG(LINFO, ("Live location: no decision possible:", e.what()));
    EndSession(pairingId,
               Now() >= session->GetInvite().m_expiresAt ? PairingInfo::Stage::Expired : PairingInfo::Stage::Cancelled);
    return;
  }
  PublishPairing(pairingId, *outcome.m_publish);
  if (!accept)
  {
    EndSession(pairingId, PairingInfo::Stage::Declined);
    return;
  }
  Peer & peer = AddPeer(outcome.m_contact);
  peer.m_contact->m_verified = compared;
  session->m_stage = PairingInfo::Stage::Connected;
  session->m_contactId = peer.m_id;
  session->m_peerName = peer.m_contact->m_name;
  Save();
  UpdateConnections();
  NotifyContacts();
  m_listener.OnPairing(Info(*session));
}

void Manager::CancelPairing(std::string const & pairingId)
{
  EndSession(pairingId, PairingInfo::Stage::Cancelled);
}

// --- Contacts -------------------------------------------------------------------------------

void Manager::RenameContact(std::string const & id, std::string name)
{
  Peer * peer = FindPeer(id);
  if (peer == nullptr || !IsValidName(name))
    return;
  peer->m_contact->m_name = std::move(name);
  Save();
  NotifyContacts();
  NotifyPositions();
}

void Manager::DeleteContact(std::string const & id)
{
  Peer * peer = FindPeer(id);
  if (peer == nullptr)
    return;
  if (m_sharer && m_sharer->IsSharing())
  {
    Recipients remaining;
    for (auto const & [contact, until] : m_sharer->GetGrants())
      if (contact != peer->m_contact)
        remaining.emplace_back(FindPeer(contact)->m_id, until);
    if (remaining.size() != m_sharer->GetGrants().size())
      ChangeSharing(remaining);
  }
  peer = FindPeer(id);
  if (peer->m_stream != 0)
    m_pool->Unsubscribe(peer->m_stream);
  for (auto & session : m_sessions)
    if (session->m_contactId == id)
      session->m_contactId.clear();
  std::erase_if(m_peers, [&](auto const & p) { return p->m_id == id; });
  Save();  // the contact's chain keys are gone: this rotates the store's keys
  UpdateConnections();
  NotifyContacts();
  NotifyPositions();
}

void Manager::MarkVerified(std::string const & id)
{
  Peer * peer = FindPeer(id);
  if (peer == nullptr)
    return;
  peer->m_contact->m_verified = true;
  peer->m_contact->m_flagged = false;
  Save();
  NotifyContacts();
}

void Manager::SetHidden(std::string const & id, bool hidden)
{
  Peer * peer = FindPeer(id);
  if (peer == nullptr || peer->m_hidden == hidden)
    return;
  peer->m_hidden = hidden;
  if (hidden)
    peer->m_following.Stop();
  Save();
  Answer(*peer);  // shown again: it learns where this user's states went meanwhile
  UpdateConnections();
  NotifyContacts();
  NotifyPositions();
}

// --- Channels -------------------------------------------------------------------------------

void Manager::PublishControl(ContactPtr const & contact, nostr::Event const & event, relay::RelayPool::DoneFn done,
                             bool ask)
{
  if (ask)
    for (auto const & url : contact->m_relays)
      AskConsent(url, contact->m_name, ConsentRequest::Purpose::Sending);
  int64_t const epoch = std::max(EpochOf(event.m_createdAt), contact->m_outgoing.Epoch());
  std::weak_ptr<int> alive = m_alive;
  m_pool->Publish(relay::EpochScope(epoch), Allowed(contact->m_relays), event,
                  [this, alive, contact, relays = contact->m_relays, done = std::move(done)](bool delivered)
  {
    if (!alive.expired())
    {
      if (Peer * peer = FindPeer(contact))
      {
        peer->m_answering = false;
        if (delivered && peer->m_deliveredTo != relays)
        {
          peer->m_deliveredTo = relays;
          Save();
        }
      }
    }
    if (done)
      done(delivered);
  });
}

bool Manager::NoteMoved(Peer & peer, bool viaHome)
{
  // Something new from the contact came through one of this user's home relays: what it sends from now
  // on arrives without the previous ones (spec §11). A relay that was in both lists counts: the contact
  // reaches the user there.
  if (!viaHome || !peer.m_notMoved)
    return false;
  peer.m_notMoved = false;
  return true;
}

void Manager::OnInboxEvent(nostr::Event const & event, bool viaHome)
{
  // The share's own stream, sent back for the echo check, is nobody's state: no key derivations for it.
  if (m_sharer && m_sharer->GetStream() && event.m_pubkey == m_sharer->GetStream()->Pubkey())
    return;
  int64_t const now = Now();
  if (event.m_kind == kKindStored)
  {
    for (auto & peer : m_peers)
    {
      if (auto const state = ReadControl(*peer->m_contact, event, now))
      {
        NoteMoved(*peer, viaHome);
        OnState(*peer, *state, event.m_createdAt);  // saves, and stops reading the old relays once all moved
        return;
      }
    }
  }
  else if (event.m_kind == kKindSignal)
  {
    for (auto & peer : m_peers)
    {
      bool const confirmed = peer->m_contact->m_confirmed;
      if (auto const watch = ReadSignal(*peer->m_contact, event, now))
      {
        bool const moved = NoteMoved(*peer, viaHome);
        if (!confirmed || moved)
        {
          Save();
          NotifyContacts();
        }
        if (moved)
          UpdateConnections();
        OnWatch(*peer, *watch);
        return;
      }
    }
  }
}

void Manager::OnState(Peer & peer, State const & state, int64_t createdAt)
{
  peer.m_contact->m_relays = state.m_relays;  // the contact's current relays, in its order
  peer.m_color = state.m_color && DotColorRgba(*state.m_color) ? *state.m_color : std::string();
  Answer(peer);
  std::string const oldPk = peer.m_following.Grant() ? peer.m_following.Grant()->m_pk : std::string();
  if (!peer.m_hidden)
    peer.m_following.OnState(state, Now());
  auto const & grant = peer.m_following.Grant();
  if (grant && grant->m_pk != oldPk)
  {
    peer.m_streamEpoch = EpochOf(createdAt);
    if (m_foreground)
    {
      auto const asks = SplitRelays(state.m_relays, Trusted()).second;
      for (auto const & url : asks)
      {
        bool const listening = url == state.m_relays.front() && m_settings.m_requestLive;
        AskConsent(url, peer.m_contact->m_name,
                   listening ? ConsentRequest::Purpose::LiveUpdates : ConsentRequest::Purpose::Viewing);
      }
      if (m_settings.m_requestLive)
        SendWatch(peer);
    }
  }
  Save();  // the last seq, the relays, the confirmation
  UpdateConnections();
  NotifyContacts();
  NotifyPositions();
}

void Manager::Answer(Peer & peer)
{
  // A contact that names other relays than those this user's last state reached gets the current state
  // there, so that it can tell when everyone has moved (spec §11). Not a hidden one; and only through a
  // relay the user allows, which may come later. The user is asked only when none is allowed: each relay
  // is asked about once, and a question asked here would take the place of one that says what the relay
  // is for, such as live updates once the contact shares.
  Contact & contact = *peer.m_contact;
  if (contact.m_relays == peer.m_deliveredTo || peer.m_hidden || peer.m_answering)
    return;
  if (Allowed(contact.m_relays).empty())
  {
    for (auto const & url : contact.m_relays)
      AskConsent(url, contact.m_name, ConsentRequest::Purpose::Sending);
    return;
  }
  peer.m_answering = true;
  int64_t const now = Now();
  bool const sharing = m_sharer && m_sharer->IsSharing();
  nostr::Event const answer = sharing ? m_sharer->CurrentState(peer.m_contact, m_rng, now)
                                      : StateEvent(contact, m_settings.m_homeRelays, std::nullopt, m_rng, now, Color());
  Save();  // its seq and created_at, before it leaves
  PublishControl(peer.m_contact, answer, {}, false /* ask */);
}

void Manager::OnWatch(Peer & peer, Watch const & watch)
{
  if (!m_sharer || !m_sharer->IsSharing() || !m_settings.m_allowLive)
    return;
  auto const & grants = m_sharer->GetGrants();
  if (std::none_of(grants.begin(), grants.end(), [&](auto const & g) { return g.first == peer.m_contact; }))
    return;  // only recipients can ask for live updates
  bool const wasLive = IsLive();
  m_liveUntil = std::max(m_liveUntil, std::min(watch.m_until, Now() + m_config.m_watchLease));
  if (!wasLive && IsLive())
  {
    UpdateLocationRequest();
    MaybePublishLocation(true);
    NotifySharing();
  }
  ScheduleClock();
}

void Manager::OnStreamEvent(std::string const & peerId, nostr::Event const & event)
{
  Peer * peer = FindPeer(peerId);
  if (peer == nullptr)
    return;
  auto const message = peer->m_following.OnStream(event, Now());
  if (!message)
    return;
  if (std::holds_alternative<StreamEnd>(*message))
    UpdateConnections();  // the stream key is gone
  NotifyPositions();
}

void Manager::SendConfirmations()
{
  bool const sharing = m_sharer && m_sharer->IsSharing();
  if (!m_started || (!m_foreground && !sharing))
    return;  // "each UTC day it runs": while the app is used, never just for this
  int64_t const now = Now();
  // After a change of home relays, every contact that has not moved yet gets the current state once a day
  // (§11), also after the 30 days in which the previous relays are read: whenever it opens its app, it
  // should still hear of the move.
  std::vector<std::pair<ContactPtr, nostr::Event>> due;
  for (auto const & peer : m_peers)
  {
    Contact const & contact = *peer->m_contact;
    bool const announce =
        peer->m_notMoved && !OfferRemoval(contact, now) && EpochOf(contact.m_lastCreatedOut) < EpochOf(now);
    if (!ConfirmationDue(contact, now) && !announce)
      continue;
    // The current state: with the grant while sharing with the contact, so that it never ends a share.
    due.emplace_back(peer->m_contact, sharing ? m_sharer->CurrentState(peer->m_contact, m_rng, now)
                                              : StateEvent(*peer->m_contact, m_settings.m_homeRelays, std::nullopt,
                                                           m_rng, now, Color()));
  }
  if (due.empty())
    return;
  Save();  // the seq and created_at of these states, before they leave
  for (auto const & [contact, event] : due)
    PublishControl(contact, event);
}

void Manager::SendWatch(Peer & peer)
{
  Relays const relays = Allowed(peer.m_contact->m_relays);
  if (relays.empty())
    return;
  int64_t const now = Now();
  nostr::Event const event = WatchSignal(*peer.m_contact, now + m_config.m_watchLease, m_rng, now);
  int64_t const epoch = std::max(EpochOf(now), peer.m_contact->m_outgoing.Epoch());
  m_pool->Publish(relay::EpochScope(epoch), relays, event);
}

void Manager::SendWatchSignals()
{
  if (!m_started || !m_foreground || !m_settings.m_requestLive)
    return;
  for (auto & peer : m_peers)
    if (!peer->m_hidden && peer->m_following.Grant())
      SendWatch(*peer);
}

// --- Sharing --------------------------------------------------------------------------------

Grants Manager::ToGrants(Recipients const & recipients) const
{
  Grants grants;
  for (auto const & [id, until] : recipients)
  {
    for (auto const & peer : m_peers)
      if (peer->m_id == id)
        grants.emplace_back(peer->m_contact, until);
  }
  return grants;
}

bool Manager::StartSharing(Recipients const & recipients)
{
  if (!m_started || recipients.empty())
    return false;
  if (m_sharer && m_sharer->IsSharing())
    return ChangeSharing(recipients);
  int64_t const now = Now();
  for (auto const & [id, until] : recipients)
  {
    Peer const * peer = FindPeer(id);
    if (peer == nullptr || peer->m_contact->m_flagged || (until != 0 && until <= now))
      return false;
  }
  m_shareRelays = m_settings.m_homeRelays;
  m_sharer = std::make_unique<Sharer>(m_shareRelays);
  m_sharer->SetColor(Color());
  Rekey rekey = m_sharer->Start(ToGrants(recipients), m_rng, now);
  m_resumable.clear();
  m_lastFix.reset();  // a fix from before the share could be hours old
  m_battery = -1;     // and so could the battery level
  m_charging = false;
  m_batteryArmed = false;
  m_lastPublished.reset();
  m_liveUntil = 0;
  Save();
  PublishRekey(std::move(rekey), m_sharer->StreamEpoch(), m_shareRelays);
  UpdateLocationRequest();
  ScheduleClock();
  UpdateConnections();
  NotifySharing();
  NotifyContacts();
  return true;
}

bool Manager::ChangeSharing(Recipients const & recipients)
{
  if (!m_sharer || !m_sharer->IsSharing())
    return StartSharing(recipients);
  if (recipients.empty())
  {
    StopSharing();
    return true;
  }
  int64_t const now = Now();
  for (auto const & [id, until] : recipients)
  {
    Peer const * peer = FindPeer(id);
    if (peer == nullptr || (until != 0 && until <= now))
      return false;
    bool const current = std::any_of(m_sharer->GetGrants().begin(), m_sharer->GetGrants().end(),
                                     [&](auto const & g) { return g.first == peer->m_contact; });
    if (!current && peer->m_contact->m_flagged)
      return false;
  }
  int64_t const oldEpoch = m_sharer->StreamEpoch();
  Rekey rekey = m_sharer->Change(ToGrants(recipients), m_rng, now);
  m_lastPublished.reset();
  Save();
  PublishRekey(std::move(rekey), oldEpoch, m_shareRelays);
  ScheduleStreamStart();
  ScheduleClock();
  UpdateConnections();  // the listening REQ asks for the new stream
  NotifySharing();
  NotifyContacts();
  return true;
}

bool Manager::ExtendSharing(std::string const & id, int64_t until)
{
  Peer * peer = FindPeer(id);
  if (peer == nullptr || !m_sharer || !m_sharer->IsSharing())
    return false;
  nostr::Event event;
  try
  {
    event = m_sharer->Extend(peer->m_contact, until, m_rng, Now());
  }
  catch (std::invalid_argument const &)
  {
    return false;
  }
  Save();
  PublishControl(peer->m_contact, event);
  ScheduleClock();
  NotifySharing();
  NotifyContacts();
  return true;
}

void Manager::StopSharing()
{
  if (!m_sharer || !m_sharer->IsSharing())
  {
    DismissResume();
    return;
  }
  int64_t const oldEpoch = m_sharer->StreamEpoch();
  Rekey rekey = m_sharer->Stop(m_rng, Now());
  m_sharer.reset();
  m_resumable.clear();
  Save();
  PublishRekey(std::move(rekey), oldEpoch, m_shareRelays);
  EndSharing();
}

void Manager::EndSharing()
{
  m_sharer.reset();
  m_lastFix.reset();
  m_lastPublished.reset();
  m_liveUntil = 0;
  Cancel(m_heartbeat);
  Cancel(m_streamStart);
  UpdateLocationRequest();
  ScheduleClock();
  UpdateConnections();
  NotifySharing();
  NotifyContacts();
}

void Manager::DismissResume()
{
  if (m_resumable.empty())
    return;
  m_resumable.clear();
  Save();
  NotifySharing();
}

void Manager::PublishRekey(Rekey rekey, int64_t oldStreamEpoch, Relays endRelays)
{
  // States first; the old stream's end once each state has an OK, or after kOkWait (spec §9).
  auto end = std::make_shared<std::optional<nostr::Event>>(std::move(rekey.m_end));
  auto pending = std::make_shared<size_t>(rekey.m_states.size());
  Relays const relays = std::move(endRelays);
  std::weak_ptr<int> alive = m_alive;
  auto const sendEnd = [this, alive, end, relays, oldStreamEpoch]
  {
    if (alive.expired() || !*end)
      return;
    nostr::Event const event = std::move(**end);
    end->reset();
    m_pool->Publish(relay::EpochScope(oldStreamEpoch), relays, event);
  };
  for (auto const & [contact, event] : rekey.m_states)
  {
    PublishControl(contact, event, [pending, sendEnd](bool)
    {
      if (--*pending == 0)
        sendEnd();
    });
  }
  if (rekey.m_states.empty())
    sendEnd();
  else if (*end)
    Later(kOkWait * 1000, sendEnd);
}

bool Manager::IsLive() const
{
  return m_settings.m_allowLive && Now() < m_liveUntil;
}

void Manager::UpdateLocationRequest()
{
  LocationRequest request = LocationRequest::Off;
  if (m_sharer && m_sharer->IsSharing())
    request = IsLive() ? LocationRequest::Live : LocationRequest::Idle;
  if (request == m_locationRequest)
    return;
  m_locationRequest = request;
  m_listener.OnLocationRequest(request);
}

void Manager::OnLocation(Location const & fix)
{
  auto checked = Checked(fix);
  if (!checked)
    return;
  m_lastFix = std::move(checked);
  MaybePublishLocation(false);
}

void Manager::OnBatteryLevel(int percent, bool charging)
{
  m_battery = percent;
  m_charging = charging;
  int const stop = m_settings.m_lowBatteryStop;  // 0: never
  if (!m_sharer || !m_sharer->IsSharing() || stop == 0)
    return;
  // A share started at or below the level is the user's choice: it runs until the battery has been above.
  // Charging does not count as above, and while the phone charges, the share does not stop for the battery.
  if (percent > stop)
    m_batteryArmed = true;
  else if (m_batteryArmed && !charging)
    StopSharing();
}

void Manager::MaybePublishLocation(bool force)
{
  if (!m_sharer || !m_sharer->IsSharing() || !m_lastFix)
    return;
  int64_t const nowMs = m_executor.NowMs();
  if (!force && m_lastPublished)
  {
    int64_t const elapsed = nowMs - m_lastPublishMs;
    double const moved = DistanceM(*m_lastPublished, *m_lastFix);
    if (IsLive())
    {
      if (elapsed < m_config.m_liveMinIntervalMs ||
          (moved < m_config.m_liveMinMoveM && elapsed < m_config.m_liveMaxSilenceMs))
      {
        return;
      }
    }
    else if (elapsed < m_config.m_idleMinIntervalMs)
    {
      return;
    }
    else
    {
      // A move only when the two fixes' accuracy circles do not overlap: a phone that lies still, with
      // the jumps of balanced accuracy, does not publish every fix. Or a fix at least twice as accurate
      // as the one viewers have. Otherwise the heartbeat publishes.
      double const threshold = std::max(m_config.m_idleMinMoveM, m_lastPublished->m_acc + m_lastFix->m_acc);
      bool const sharper = m_lastPublished->m_acc > 0 && m_lastFix->m_acc * 2 <= m_lastPublished->m_acc;
      if (moved < threshold && !sharper)
        return;
    }
  }
  Location fix = *m_lastFix;
  if (m_battery >= 0 && m_battery <= m_config.m_lowBattery && !m_charging)
    fix.m_low = true;  // viewers say so (spec §9)
  auto const event = m_sharer->PublishLocation(fix, m_rng, Now());
  if (!event)
    return;  // a new stream, silent for now: ScheduleStreamStart() publishes when it may
  m_pool->Publish(relay::EpochScope(m_sharer->StreamEpoch()), m_shareRelays, *event);
  m_lastPublished = m_lastFix;
  m_lastPublishMs = nowMs;
  Cancel(m_heartbeat);
  m_heartbeat = Later(m_config.m_heartbeatMs, [this] { MaybePublishLocation(true); });
}

void Manager::ScheduleStreamStart()
{
  Cancel(m_streamStart);
  if (!m_sharer || !m_sharer->IsSharing())
    return;
  m_streamStart = Later(m_sharer->NotBefore() * 1000 - m_executor.NowMs(), [this]
  {
    m_streamStart = Executor::kNoTask;
    MaybePublishLocation(true);
  });
}

// --- Time and connections -------------------------------------------------------------------

void Manager::ScheduleClock()
{
  Cancel(m_clock);
  if (!m_started)
    return;
  int64_t const now = Now();
  int64_t next = EpochEnd(EpochOf(now));                                // midnight: a new epoch
  int64_t const graceEnd = EpochEnd(EpochOf(now) - 1) + kControlGrace;  // 01:00: yesterday's keys go
  if (graceEnd > now)
    next = std::min(next, graceEnd);
  for (auto const & session : m_sessions)
    next = std::min(next, std::max(now, session->GetInvite().m_expiresAt));
  if (m_sharer && m_sharer->IsSharing())
    for (auto const & grant : m_sharer->GetGrants())
      if (grant.second != 0)
        next = std::min(next, std::max(now, grant.second));
  if (m_liveUntil > now)
    next = std::min(next, m_liveUntil);
  m_clock = Later(next * 1000 - m_executor.NowMs(), [this]
  {
    m_clock = Executor::kNoTask;
    OnClock();
  });
}

void Manager::OnClock()
{
  int64_t const now = Now();
  for (auto & peer : m_peers)
    Ratchet(*peer->m_contact, now);  // CK(e) goes at epoch_end(e) + 3600 (spec §7)

  std::vector<std::string> expired;
  for (auto const & session : m_sessions)
    if (now >= session->GetInvite().m_expiresAt)
      expired.push_back(session->m_id);
  for (auto const & id : expired)
  {
    // A finished pairing just stops watching for conflicts; an unfinished one has expired.
    bool const connected = FindSession(id)->m_stage == PairingInfo::Stage::Connected;
    EndSession(id, connected ? PairingInfo::Stage::Connected : PairingInfo::Stage::Expired, !connected);
  }

  if (m_sharer && m_sharer->IsSharing())
  {
    int64_t const oldEpoch = m_sharer->StreamEpoch();
    if (auto rekey = m_sharer->Tick(m_rng, now))
    {
      Save();
      PublishRekey(std::move(*rekey), oldEpoch, m_shareRelays);
      if (!m_sharer->IsSharing())
      {
        EndSharing();
      }
      else
      {
        m_lastPublished.reset();
        ScheduleStreamStart();
        NotifySharing();
        NotifyContacts();
      }
    }
  }
  if (m_liveUntil != 0 && now >= m_liveUntil)
  {
    m_liveUntil = 0;
    UpdateLocationRequest();
    NotifySharing();
  }
  SendConfirmations();
  Save();  // rotates the store's keys when chain keys were erased
  UpdateConnections();
  ScheduleClock();
  NotifyContacts();  // labels that time changes: removal offered, a move overdue
}

std::vector<nostr::Filter> Manager::InboxRequest(int64_t epoch, bool listening) const
{
  std::vector<ContactPtr> contacts;
  for (auto const & peer : m_peers)
    contacts.push_back(peer->m_contact);
  auto filters = InboxFilters(contacts, m_decoySeed, epoch, Now());
  // On the listening relay, the share's own stream too, so that its events come back over the connection
  // that publishes them: one that does not shows a relay that accepts them without delivering anything,
  // and the REQ moves to the next relay (the echo check, relay pool). Only a stream of the inbox's epoch:
  // a connection carries one epoch's keys (spec §11).
  if (listening && !filters.empty() && m_sharer && m_sharer->GetStream() && m_sharer->StreamEpoch() == epoch)
    filters.push_back({{kKindStored}, {m_sharer->GetStream()->Pubkey()}, {}, {}});
  return filters;
}

void Manager::UpdateConnections()
{
  if (!m_started)
    return;
  int64_t const now = Now();
  int64_t const epoch = EpochOf(now);
  bool const sharing = m_sharer && m_sharer->IsSharing();
  std::vector<ContactPtr> contacts;
  for (auto const & peer : m_peers)
    contacts.push_back(peer->m_contact);

  // The inbox: states and signals from every contact, on the home relays. In the foreground on all of
  // them; while only sharing, on the listening relay (D17). Otherwise nothing at all.
  bool const listening = !m_foreground;
  auto const filters = InboxRequest(epoch, listening);
  std::vector<std::string> authors;
  for (auto const & filter : filters)
    if (filter.m_kinds == std::vector<int64_t>{kKindStored})
      authors.insert(authors.end(), filter.m_authors.begin(), filter.m_authors.end());
  bool const wantInbox = !filters.empty() && (m_foreground || sharing);
  relay::Scope const scope = relay::EpochScope(epoch);
  relay::Placement const placement = m_foreground ? relay::Placement::All : relay::Placement::FirstReachable;
  // While only sharing, the inbox listens on the listening relay of the home relays alone (D17): viewers
  // send their signals to the list the share names.
  Relays const & inboxRelays = m_settings.m_homeRelays;
  if (m_inbox != 0 &&
      (!wantInbox || scope != m_inboxScope || placement != m_inboxPlacement || inboxRelays != m_inboxRelays))
  {
    m_pool->Unsubscribe(m_inbox);
    m_inbox = 0;
  }
  if (wantInbox && m_inbox == 0)
  {
    m_inboxScope = scope;
    m_inboxPlacement = placement;
    m_inboxRelays = inboxRelays;
    m_inboxAuthors = authors;
    m_inbox = m_pool->Subscribe(scope, inboxRelays, placement, [this, epoch, listening]
    { return InboxRequest(epoch, listening); }, [this](nostr::Event const & event) { OnInboxEvent(event, true); });
  }
  else if (wantInbox && authors != m_inboxAuthors)
  {
    m_inboxAuthors = authors;
    m_pool->Refresh(m_inbox);
    if (m_oldInbox != 0)
      m_pool->Refresh(m_oldInbox);
  }

  // The previous home relays, while the map is open, until every contact has moved (spec §11): what
  // arrives there tells nothing of a move.
  Relays const oldRelays = m_foreground && wantInbox ? OldRelays() : Relays();
  if (m_oldInbox != 0 && (oldRelays.empty() || scope != m_oldInboxScope || oldRelays != m_oldInboxRelays))
  {
    m_pool->Unsubscribe(m_oldInbox);
    m_oldInbox = 0;
  }
  if (!oldRelays.empty() && m_oldInbox == 0)
  {
    m_oldInboxScope = scope;
    m_oldInboxRelays = oldRelays;
    m_oldInbox = m_pool->Subscribe(scope, oldRelays, relay::Placement::All, [this, epoch]
    { return InboxRequest(epoch, false); }, [this](nostr::Event const & event) { OnInboxEvent(event, false); });
  }

  // In the first hour of a day, contacts' latest states may still be signed with yesterday's keys:
  // read them once, over connections of yesterday's scope (spec §11).
  int64_t const graceEnd = EpochEnd(epoch - 1) + kControlGrace;
  if (m_foreground && now < graceEnd && m_catchUp == 0 && !contacts.empty())
  {
    std::vector<nostr::Filter> previous;
    for (auto const & filter : InboxFilters(contacts, m_decoySeed, epoch - 1, now))
      if (filter.m_kinds == std::vector<int64_t>{kKindStored})
        previous.push_back(filter);
    if (!previous.empty())
    {
      Relays relays = m_settings.m_homeRelays;
      for (auto const & url : OldRelays())
        relays.push_back(url);
      m_catchUp = m_pool->Subscribe(relay::EpochScope(epoch - 1), relays, relay::Placement::All, [previous]
      { return previous; }, [this](nostr::Event const & event) { OnInboxEvent(event, false); });
      Later(kCatchUpMs, [this]
      {
        if (m_catchUp != 0)
          m_pool->Unsubscribe(m_catchUp);
        m_catchUp = 0;
      });
    }
  }

  // Streams of contacts sharing with this user, while the map shows them.
  for (auto & peer : m_peers)
  {
    auto const & grant = peer->m_following.Grant();
    bool const want = m_foreground && !peer->m_hidden && grant.has_value();
    Relays const relays = want ? Allowed(peer->m_contact->m_relays) : Relays();
    if (peer->m_stream != 0 &&
        (!want || grant->m_pk != peer->m_streamPk || relays != peer->m_streamRelays || relays.empty()))
    {
      m_pool->Unsubscribe(peer->m_stream);
      peer->m_stream = 0;
    }
    if (want && peer->m_stream == 0 && !relays.empty())
    {
      std::string const pk = grant->m_pk;
      std::string const id = peer->m_id;
      peer->m_streamPk = pk;
      peer->m_streamRelays = relays;
      peer->m_stream = m_pool->Subscribe(relay::EpochScope(peer->m_streamEpoch), relays, relay::Placement::All,
                                         [pk] { return std::vector<nostr::Filter>{{{kKindStored}, {pk}, {}, {}}}; },
                                         [this, id](nostr::Event const & event) { OnStreamEvent(id, event); });
    }
  }

  // Pairings, while the app is in the foreground and until each invite expires.
  for (auto & session : m_sessions)
  {
    bool const want = m_foreground && session->Watching() && now < session->GetInvite().m_expiresAt;
    if (!want && session->m_subscription != 0)
    {
      m_pool->Unsubscribe(session->m_subscription);
      session->m_subscription = 0;
    }
    if (want && session->m_subscription == 0)
    {
      std::string const ipk = ToHex(session->GetInvite().m_ipk);
      std::string const id = session->m_id;
      bool const joiner = session->m_joiner != nullptr;
      session->m_subscription = m_pool->Subscribe(relay::PairingScope(id), Allowed(session->GetInvite().m_relays),
                                                  relay::Placement::All, [ipk, joiner]
      {
        std::vector<nostr::Filter> filters = {{{kKindStored}, {}, {ipk}, {}}};
        if (joiner)
          filters.push_back({{kKindStored}, {ipk}, {}, {}});
        return filters;
      }, [this, id](nostr::Event const & event) { OnPairingEvent(id, event); });
      std::vector<nostr::Event> const unsent = session->m_unsent;
      for (auto const & event : unsent)
        PublishPairing(id, event);
    }
  }

  // Watch signals while viewing (D4), and the view's clock.
  bool viewing = false;
  for (auto const & peer : m_peers)
    viewing = viewing || (!peer->m_hidden && (peer->m_following.Grant() || peer->m_following.Position()));
  bool const wantWatch = m_foreground && m_settings.m_requestLive && viewing;
  if (wantWatch && m_watchTimer == Executor::kNoTask)
  {
    m_watchTimer = Later(m_config.m_watchIntervalMs, [this]
    {
      m_watchTimer = Executor::kNoTask;
      SendWatchSignals();
      UpdateConnections();
    });
  }
  else if (!wantWatch)
  {
    Cancel(m_watchTimer);
  }
  if (m_foreground && viewing && m_viewTimer == Executor::kNoTask)
  {
    m_viewTimer = Later(m_config.m_viewTickMs, [this]
    {
      m_viewTimer = Executor::kNoTask;
      ViewTick();
    });
  }
  else if (!(m_foreground && viewing))
  {
    Cancel(m_viewTimer);
  }
}

void Manager::ViewTick()
{
  int64_t const now = Now();
  for (auto & peer : m_peers)
  {
    peer->m_following.Tick(now);  // a stale position goes kEndGrace after its stream's end
    auto const & grant = peer->m_following.Grant();
    if (grant && grant->m_until != 0 && grant->m_until <= now)
      peer->m_following.Stop();  // the time limit is enforced locally too
  }
  NotifyPositions();
  NotifyContacts();
  UpdateConnections();
}

// --- Views ----------------------------------------------------------------------------------

std::vector<ContactInfo> Manager::Contacts() const
{
  int64_t const now = Now();
  auto const trusted = Trusted();
  std::vector<ContactInfo> out;
  for (auto const & peer : m_peers)
  {
    Contact const & contact = *peer->m_contact;
    ContactInfo info;
    info.m_id = peer->m_id;
    info.m_name = contact.m_name;
    info.m_sas = contact.m_sas;
    info.m_verified = contact.m_verified;
    info.m_flagged = contact.m_flagged;
    info.m_waiting = !contact.m_confirmed;
    info.m_offerRemoval = OfferRemoval(contact, now);
    info.m_hidden = peer->m_hidden;
    // A contact that never finished connecting is offered for removal instead.
    info.m_notMoved = peer->m_notMoved && m_settings.m_relaysChanged != 0 && !info.m_offerRemoval;
    info.m_moveOverdue = info.m_notMoved && !MoveWindow();
    info.m_color = peer->m_color;
    if (!contact.m_relays.empty() && SplitRelays(contact.m_relays, trusted).first.empty())
      info.m_blockedRelay = contact.m_relays.front();
    if (auto const & grant = peer->m_following.Grant())
    {
      info.m_sharesWithMeUntil = grant->m_until;
      if (auto relay = MissingListeningRelay(contact.m_relays, trusted); relay && m_settings.m_requestLive)
      {
        info.m_liveUpdatesOff = true;
        info.m_liveRelay = std::move(*relay);
      }
    }
    if (m_sharer && m_sharer->IsSharing())
      for (auto const & [c, until] : m_sharer->GetGrants())
        if (c == peer->m_contact)
          info.m_iShareUntil = until;
    out.push_back(std::move(info));
  }
  return out;
}

std::vector<PairingInfo> Manager::Pairings() const
{
  std::vector<PairingInfo> out;
  for (auto const & session : m_sessions)
    out.push_back(Info(*session));
  return out;
}

std::vector<PositionInfo> Manager::Positions() const
{
  int64_t const now = Now();
  std::vector<PositionInfo> out;
  for (auto const & peer : m_peers)
  {
    auto const & position = peer->m_following.Position();
    if (!position || peer->m_hidden)
      continue;
    PositionInfo info;
    info.m_contactId = peer->m_id;
    info.m_name = peer->m_contact->m_name;
    info.m_location = *position;
    info.m_stale = peer->m_following.IsStale() || now - position->m_ts / 1000 > m_config.m_staleAfter;
    info.m_color = peer->m_color;
    out.push_back(std::move(info));
  }
  return out;
}

SharingInfo Manager::Sharing() const
{
  SharingInfo info;
  int64_t const now = Now();
  for (auto const & [id, until] : m_resumable)
    if (until == 0 || until > now)  // not one whose end has passed since
      info.m_resumable.emplace_back(id, until);
  if (!m_sharer || !m_sharer->IsSharing())
    return info;
  info.m_active = true;
  info.m_live = IsLive();
  for (auto const & [contact, until] : m_sharer->GetGrants())
    for (auto const & peer : m_peers)
      if (peer->m_contact == contact)
        info.m_recipients.emplace_back(peer->m_id, until);
  return info;
}

void Manager::NotifyContacts()
{
  m_listener.OnContacts(Contacts());
}

void Manager::NotifyPositions()
{
  m_listener.OnPositions(Positions());
}

void Manager::NotifySharing()
{
  m_listener.OnSharing(Sharing());
}
}  // namespace live_location
