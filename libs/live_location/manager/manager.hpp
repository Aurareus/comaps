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
  /// The store was read, or deleted: the settings are the user's, and edits take.
  bool IsStarted() const { return m_started; }
  bool SetName(std::string name);
  /// Contacts learn the new list from a state sent to each of them now, and answer through it. Until every
  /// contact has sent something through the new list, for at most 30 days, the previous relays are still
  /// read, and each contact that has not gets the state again on each day the app runs (spec §11). A
  /// running share is re-keyed onto the new list.
  bool SetHomeRelays(Relays relays);
  /// The user's answer about a relay (relay consent, spec §11). Approvals and refusals are kept until
  /// revoked; "not now" lasts for this run.
  void SetConsent(std::string const & url, Consent consent, std::string const & forContact);
  void RevokeConsent(std::string const & url);
  void SetRequestLive(bool request);
  void SetAllowLive(bool allow);
  /// The dot colour contacts see: a name of kDotColors, or "" to let each viewer pick. The current
  /// recipients get a state with it at once, everyone else with their next one (spec §8).
  bool SetColor(std::string color);
  /// Sharing stops at this battery level, 0..50 percent; 0: never.
  bool SetLowBatteryStop(int percent);

  /// The inviter's side: a QR code lives 10 minutes, a link a day. Nothing without a valid name.
  std::optional<PairingInfo> CreateInvite(bool byLink);
  /// The joiner's side. Nothing for an invalid or expired link, or without a valid name. When the
  /// invite uses relays the user has not allowed, the result asks for them (NeedsConsent); call again
  /// once they are answered. When the user refused or put off all of them, it is Cancelled and names them.
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
  /// Another time limit for a current recipient, earlier or later (same stream).
  bool ExtendSharing(std::string const & id, int64_t until);
  void StopSharing();
  void DismissResume();
  /// A fix from the location provider. Its m_ts is the fix time in milliseconds.
  void OnLocation(Location const & fix);
  /// The battery level, in percent, and whether the phone charges. At or below m_lowBattery positions say
  /// so, and at or below the user's stop level the share stops, both only while the phone does not charge;
  /// and the share does not stop when it started at or below the level and the battery has not been above.
  void OnBatteryLevel(int percent, bool charging);

  std::vector<ContactInfo> Contacts() const;
  std::vector<PairingInfo> Pairings() const;
  std::vector<PositionInfo> Positions() const;
  SharingInfo Sharing() const;
  /// Whether something sent still waits for relays' answers, e.g. the ends of a share just stopped.
  /// An app that stops keeps the manager until it has none, so that a stop reaches the relays.
  bool HasPendingPublications() const { return m_pool->HasPendingPublications(); }
  /// Sends what is due (spec §8): contacts' latest states that no relay has accepted yet, again until one does
  /// (with the app off screen, for a week at most); a share's end once more on a later UTC day; the ends of
  /// shares with deleted contacts. The manager also
  /// does this by itself: when a relay connection opens, on a back-off after a failure, at midnight, and when
  /// the app comes to the foreground. Call it after Start() when the app runs the core for this.
  void Deliver();
  /// When something is next to be sent (Unix seconds; at or before now: now), 0 for nothing; with the app off
  /// screen, so nothing for a contact whose relays have accepted none of the user's states for a week. It
  /// changes with what is to be sent, not with each attempt to send it, nor while one waits for the relays'
  /// answers.
  int64_t DeliveryDue() const;
  /// For tests and diagnostics.
  relay::RelayPool const & Pool() const { return *m_pool; }

private:
  struct Peer;
  struct Session;
  struct Departed;

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
  Departed * FindDeparted(std::string const & id);
  std::set<std::string> Trusted() const;
  /// The 30 days after a change of home relays (spec §11) ...
  bool MoveWindow() const;
  /// ... while some contact has not moved to the new relays yet.
  bool MovePending() const;
  /// The previous home relays that are no longer home relays, while MovePending().
  Relays OldRelays() const;
  /// The user's dot colour for states, if any.
  std::optional<std::string> Color() const;
  /// A relay sent an event back to the connection that published it (the echo check).
  void OnEchoed(std::string const & url);
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
  /// A share to follow from now on: its relays asked about where needed, live updates asked for (D4).
  void StartFollowing(Peer & peer);
  /// What has ended by `now`: a stale position kEndGrace after its stream's end, a share past its time limit.
  void ExpireFollowing(Peer & peer, int64_t now);
  void OnWatch(Peer & peer, Watch const & watch);
  void OnStreamEvent(std::string const & peerId, nostr::Event const & event);
  /// States, each the latest towards its contact, to the contact's relays that the user allows; saved first.
  /// Each counts as not delivered until a relay accepts it (spec §8). `answered`: once each has an answer, or
  /// failed. `ask`: about the other relays, once each (relay consent).
  void PublishStates(std::vector<std::pair<ContactPtr, nostr::Event>> const & states,
                     std::function<void()> answered = {}, bool ask = true);
  /// The same, for states that are already saved as the latest, e.g. sent again.
  void SendStates(std::vector<std::pair<ContactPtr, nostr::Event>> const & states, std::function<void()> answered,
                  bool ask);
  void OnStateAnswered(std::string const & id, nostr::Event const & event, Relays const & relays, bool delivered);
  /// Whether the contact is owed the current state: its relays do not hold this user's latest state, because
  /// no relay accepted that yet, or because the contact moved (the answer, spec §11, never to a hidden one).
  /// With the app off screen, not once they have accepted nothing for a week (Overdue()).
  bool Owed(Peer const & peer) const;
  /// Whether the contact's relays have accepted none of the user's states for a week (kBackgroundRetrySeconds).
  bool Overdue(Peer const & peer) const;
  /// A recipient of a share that the process's death interrupted: until the user resumes it or not, the contact
  /// sees it as it was, and nothing goes to it.
  bool Interrupted(Peer const & peer) const;
  void PublishDeparted(Departed & departed, nostr::Event const & event);
  /// Shares that ended with `before`'s recipients are told once more on a later day; new ones need not be.
  void NoteShareEnds(Grants const & before);
  /// Deliver() again after a failure, on a back-off.
  void ScheduleDelivery();
  void NotifyDelivery();
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
  /// `deliver`: also what is due to be sent (not at Start(): a start only to ratchet connects nowhere).
  void OnClock(bool deliver = true);
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
  bool m_writeFailing = false;  // the last write of the store failed
  bool m_foreground = false;
  Settings m_settings;
  Key m_decoySeed;
  std::vector<std::unique_ptr<Peer>> m_peers;
  std::vector<std::unique_ptr<Session>> m_sessions;
  std::vector<std::unique_ptr<Departed>> m_departed;
  std::set<std::string> m_asked;  // relays asked about in this run
  std::set<std::string> m_echoed;  // relays that have sent an event back (the echo check), kept while in use
  int m_battery = -1;              // the last level reported during the share, -1: none
  bool m_charging = false;         // and whether the phone charged then
  bool m_batteryArmed = false;     // the battery has been above the stop level during the share

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

  // Delivery
  Executor::TaskId m_delivery = Executor::kNoTask;
  int m_deliveryFailures = 0;  // in a row: the back-off
  int64_t m_notifiedDue = -1;  // as last told the app
};
}  // namespace live_location
