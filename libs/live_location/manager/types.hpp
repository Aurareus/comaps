#pragma once

#include "live_location/protocol/messages.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

// What the manager shows the app and asks of it (design doc §11).
namespace live_location
{
struct Settings
{
  std::string m_name;                             // this user's name, sent when pairing
  Relays m_homeRelays;                            // in the user's order: the first reachable one listens (D17)
  std::map<std::string, std::string> m_approved;  // relay consent: url -> the contact it was approved for
  std::set<std::string> m_declined;               // asked once and refused
  bool m_requestLive = true;                      // ask sharers for live updates while viewing (D4)
  bool m_allowLive = true;                        // honour viewers' requests for live updates (D4)
  int m_lowBatteryStop = 5;                       // stop sharing at this battery level, in percent
};

struct ContactInfo
{
  std::string m_id;
  std::string m_name;
  std::string m_sas;
  bool m_verified = false;
  bool m_flagged = false;
  bool m_waiting = false;       // the joiner has not confirmed yet (spec §6.3, design doc D18)
  bool m_offerRemoval = false;  // ... and the week of confirmations is over
  bool m_hidden = false;
  std::optional<int64_t> m_sharesWithMeUntil;  // 0: until stopped
  std::optional<int64_t> m_iShareUntil;        // 0: until stopped
  bool m_liveUpdatesOff = false;               // live updates need a relay the user has not allowed
};

struct PairingInfo
{
  enum class Stage
  {
    NeedsConsent,  // the invite names relays the user must allow first: m_needsConsent
    Waiting,       // for the other phone
    CompareCode,   // m_sas, and for the inviter the joiner's name in m_peerName: decide
    Connected,     // m_contactId
    Declined,
    Cancelled,  // by this user, or the codes differed
    Conflict,   // someone else used the invite: both sides stopped
    Expired,
  };

  std::string m_id;
  bool m_inviter = false;
  bool m_byLink = false;  // a link invite rather than a QR code: the codes are compared at a distance
  Stage m_stage = Stage::Waiting;
  std::string m_link;  // the inviter's invite
  int64_t m_expiresAt = 0;
  std::string m_sas;
  std::string m_peerName;
  std::string m_contactId;
  std::vector<std::string> m_needsConsent;
};

struct PositionInfo
{
  std::string m_contactId;
  std::string m_name;
  Location m_location;
  bool m_stale = false;  // over 2 minutes old, or its stream ended
};

struct SharingInfo
{
  bool m_active = false;
  std::vector<std::pair<std::string, int64_t>> m_recipients;  // contact id, until (0: until stopped)
  bool m_live = false;                                        // a viewer asked for live updates
  /// After the app's process died while sharing: what the user may resume (design doc §8.5).
  std::vector<std::pair<std::string, int64_t>> m_resumable;
};

struct ConsentRequest
{
  enum class Purpose
  {
    Pairing,      // the invite's relay
    Viewing,      // a sharer's relay
    LiveUpdates,  // a sharer's listening relay: live updates need it
    Sending,      // a contact's relay, to send it states
  };

  std::string m_url;
  std::string m_contactName;  // empty for pairing
  Purpose m_purpose = Purpose::Viewing;
};

/// What the location provider should deliver (design doc §10.3).
enum class LocationRequest
{
  Off,
  Idle,  // 30 s, balanced
  Live,  // 2 s, high accuracy
};

/// The app's side. Everything arrives on the manager's thread.
class ManagerListener
{
public:
  virtual ~ManagerListener() = default;
  virtual void OnContacts(std::vector<ContactInfo> const &) {}
  virtual void OnPairing(PairingInfo const &) {}
  virtual void OnPositions(std::vector<PositionInfo> const &) {}
  virtual void OnSharing(SharingInfo const &) {}
  virtual void OnConsentNeeded(ConsentRequest const &) {}
  virtual void OnLocationRequest(LocationRequest) {}
  /// The store could not be read or written; the app may offer to delete the live location data.
  virtual void OnStoreError() {}
};

/// The cadence of design doc §10.3.
struct ManagerConfig
{
  int64_t m_liveMinIntervalMs = 3'000;   // live: fixes at least 3 s apart ...
  double m_liveMinMoveM = 3;             // ... that moved at least 3 m ...
  int64_t m_liveMaxSilenceMs = 15'000;   // ... or 15 s after the last
  double m_idleMinMoveM = 50;            // idle: moved 50 m ...
  int64_t m_idleMinIntervalMs = 30'000;  // ... at least 30 s after the last
  int64_t m_heartbeatMs = 300'000;       // otherwise every 5 min
  int64_t m_watchIntervalMs = 60'000;    // viewers signal every minute
  int64_t m_watchLease = 120;            // seconds a signal keeps the sharer live
  int64_t m_staleAfter = 120;            // seconds after which a position is shown as old
  int64_t m_viewTickMs = 10'000;         // how often positions are re-checked while viewing
};
}  // namespace live_location
