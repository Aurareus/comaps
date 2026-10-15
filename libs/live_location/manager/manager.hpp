#pragma once

#include "live_location/crypto/random.hpp"
#include "live_location/executor.hpp"
#include "live_location/manager/types.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/pairing.hpp"
#include "live_location/protocol/stream.hpp"
#include "live_location/relay/relay_pool.hpp"
#include "live_location/store/store.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

// The live location state machine (design doc §8.1): pairing, sharing, viewing, the timers, the cadence
// and the connection policy. It runs on the executor's thread; so must every call into it.
namespace live_location
{
class Manager
{
public:
  using Recipients = std::vector<std::pair<std::string, int64_t>>;  // contact id, until (0: until stopped)

  Manager(Executor & executor, relay::Transport & transport, store::Store & store, crypto::Rng & rng,
          ManagerListener & listener, ManagerConfig config = {});
  ~Manager();

  Manager(Manager const &) = delete;
  Manager & operator=(Manager const &) = delete;

  /// Reads the store. False when it exists but cannot be read (OnStoreError): DeleteAllData() then
  /// starts afresh. Until one of them succeeds nothing is written, so a store that could not be read
  /// for a while (e.g. the key store failing) reads again on the next start.
  bool Start();
  /// "Delete all live-location data": stops everything, deletes the file and the keys.
  void DeleteAllData();

  /// The map is in the foreground: the user may be looking at contacts' positions (D11).
  void SetForeground(bool foreground);

  Settings const & GetSettings() const { return m_settings; }
  bool SetName(std::string name);
  /// Contacts learn the new list from a state sent to each of them now, and answer through it. Until every
  /// contact has sent something through the new list, for at most 30 days, the previous relays are still
  /// read, and each contact that has not gets the state again on each day the app runs (spec §11). A
  /// running share is re-keyed onto the new list.
  bool SetHomeRelays(Relays relays);
  /// The user's answer about a relay (relay consent, spec §11). Approvals are kept until revoked; a
  /// refusal means the app does not ask again.
  void SetConsent(std::string const & url, bool allowed, std::string const & forContact);
  void RevokeConsent(std::string const & url);
  void SetRequestLive(bool request);
  void SetAllowLive(bool allow);

  /// The inviter's side: a QR code lives 10 minutes, a link a day. Nothing without a valid name.
  std::optional<PairingInfo> CreateInvite(bool byLink);
  /// The joiner's side. Nothing for an invalid or expired link, or without a valid name. When the
  /// invite uses relays the user has not allowed, the result asks for them (NeedsConsent); call again
  /// once they are answered.
  std::optional<PairingInfo> OpenInvite(std::string const & link);
  /// The joiner compared the codes: "Codes match" marks the contact verified, "They differ" stops.
  void ConfirmCode(std::string const & pairingId, bool match);
  /// The inviter's decision; `compared`: the user checked the codes (verified).
  void Decide(std::string const & pairingId, bool accept, bool compared);
  void CancelPairing(std::string const & pairingId);

  void RenameContact(std::string const & id, std::string name);
  /// Stops any share with the contact first.
  void DeleteContact(std::string const & id);
  /// The codes were compared later: verified, and a flag is cleared.
  void MarkVerified(std::string const & id);
  /// Hiding stops every connection made for the contact's share (design doc §11.4).
  void SetHidden(std::string const & id, bool hidden);

  /// False if a recipient is unknown or flagged, or a time limit is in the past.
  bool StartSharing(Recipients const & recipients);
  /// A new set of recipients (re-keys the stream). Empty stops sharing.
  bool ChangeSharing(Recipients const & recipients);
  /// A later time limit for a current recipient (same stream).
  bool ExtendSharing(std::string const & id, int64_t until);
  void StopSharing();
  void DismissResume();
  /// A fix from the location provider. Its m_ts is the fix time in milliseconds.
  void OnLocation(Location const & fix);
  void OnBatteryLevel(int percent);

  std::vector<ContactInfo> Contacts() const;
  std::vector<PairingInfo> Pairings() const;
  std::vector<PositionInfo> Positions() const;
  SharingInfo Sharing() const;
  /// Whether something sent still waits for relays' answers, e.g. the ends of a share just stopped.
  /// An app that stops keeps the manager until it has none, so that a stop reaches the relays.
  bool HasPendingPublications() const { return m_pool->HasPendingPublications(); }
  /// For tests and diagnostics.
  relay::RelayPool const & Pool() const { return *m_pool; }

private:
  struct Peer;
  struct Session;

  // Store
  SecretBytes Encode(std::set<ByteArray<32>> & digests) const;
  void Decode(ByteSpan data);
  void Save();
  void Fresh();

  // Helpers
  int64_t Now() const { return m_executor.Now(); }
  std::string NewId();
  Peer * FindPeer(std::string const & id);
  Peer * FindPeer(ContactPtr const & contact);
  Session * FindSession(std::string const & id);
  std::set<std::string> Trusted() const;
  /// The 30 days after a change of home relays (spec §11) ...
  bool MoveWindow() const;
  /// ... while some contact has not moved to the new relays yet.
  bool MovePending() const;
  /// The previous home relays that are no longer home relays, while MovePending().
  Relays OldRelays() const;
  bool IsAllowed(std::string const & url) const;
  Relays Allowed(Relays const & relays) const;
  void AskConsent(std::string const & url, std::string const & contactName, ConsentRequest::Purpose purpose);
  Executor::TaskId Later(int64_t delayMs, std::function<void()> task);
  void Cancel(Executor::TaskId & id);

  // Pairing
  void OnPairingEvent(std::string const & sessionId, nostr::Event const & event);
  void PublishPairing(std::string const & sessionId, nostr::Event const & event);
  void HandleOutcome(Session & session, Outcome const & outcome);
  void EndSession(std::string const & sessionId, PairingInfo::Stage stage, bool notify = true);
  Peer & AddPeer(ContactPtr const & contact);
  PairingInfo Info(Session const & session) const;

  // Channels
  /// `viaHome`: through this user's home relays, rather than the previous ones.
  void OnInboxEvent(nostr::Event const & event, bool viaHome);
  bool NoteMoved(Peer & peer, bool viaHome);
  void OnState(Peer & peer, State const & state, int64_t createdAt);
  void Answer(Peer & peer);
  void OnWatch(Peer & peer, Watch const & watch);
  void OnStreamEvent(std::string const & peerId, nostr::Event const & event);
  /// To the contact's relays that the user allows. `ask`: about the others, once each (relay consent).
  void PublishControl(ContactPtr const & contact, nostr::Event const & event, relay::RelayPool::DoneFn done = {},
                      bool ask = true);
  void SendConfirmations();
  void SendWatchSignals();
  void SendWatch(Peer & peer);

  // Sharing
  Grants ToGrants(Recipients const & recipients) const;
  /// The states, then the old stream's end on `endRelays`, where that stream was published.
  void PublishRekey(Rekey rekey, int64_t oldStreamEpoch, Relays endRelays);
  void AnnounceRelays();
  void MaybePublishLocation(bool force);
  void ScheduleStreamStart();
  void EndSharing();
  bool IsLive() const;
  void UpdateLocationRequest();

  // Time and connections
  std::vector<nostr::Filter> InboxRequest(int64_t epoch, bool listening) const;
  void ScheduleClock();
  void OnClock();
  void UpdateConnections();
  void ViewTick();

  // Notifications
  void NotifyContacts();
  void NotifyPositions();
  void NotifySharing();

  Executor & m_executor;
  store::Store & m_store;
  crypto::Rng & m_rng;
  ManagerListener & m_listener;
  ManagerConfig m_config;
  std::unique_ptr<relay::RelayPool> m_pool;
  std::shared_ptr<int> m_alive = std::make_shared<int>(0);

  bool m_started = false;
  bool m_foreground = false;
  Settings m_settings;
  Key m_decoySeed;
  std::vector<std::unique_ptr<Peer>> m_peers;
  std::vector<std::unique_ptr<Session>> m_sessions;
  std::set<std::string> m_asked;  // relays asked about in this run

  // Sharing
  std::unique_ptr<Sharer> m_sharer;
  Relays m_shareRelays;  // the home relays when the share started: its states name them
  Recipients m_resumable;
  std::optional<Location> m_lastFix;
  std::optional<Location> m_lastPublished;
  int64_t m_lastPublishMs = 0;
  int64_t m_liveUntil = 0;
  LocationRequest m_locationRequest = LocationRequest::Off;
  Executor::TaskId m_heartbeat = Executor::kNoTask;
  Executor::TaskId m_streamStart = Executor::kNoTask;

  // Connections
  relay::RelayPool::SubscriptionId m_inbox = 0;
  relay::Scope m_inboxScope;
  relay::Placement m_inboxPlacement = relay::Placement::All;
  Relays m_inboxRelays;
  std::vector<std::string> m_inboxAuthors;
  relay::RelayPool::SubscriptionId m_oldInbox = 0;  // the previous home relays (spec §11)
  relay::Scope m_oldInboxScope;
  Relays m_oldInboxRelays;
  relay::RelayPool::SubscriptionId m_catchUp = 0;  // the previous epoch's states, in the grace hour
  Executor::TaskId m_clock = Executor::kNoTask;
  Executor::TaskId m_watchTimer = Executor::kNoTask;
  Executor::TaskId m_viewTimer = Executor::kNoTask;
};
}  // namespace live_location
