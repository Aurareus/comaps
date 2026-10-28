#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/messages.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// The location stream (spec §9) and the viewer's side of a share (§12).
namespace live_location
{
/// A stream: a secret signing key and a NIP-44 key shared with the current recipients.
struct Stream
{
  Key m_secret;  // signing key, the sharer's only
  Key m_key;     // conversation key, in the grants
  int64_t m_seq = 0;
  int64_t m_lastCreated = 0;

  static Stream Create(crypto::Rng & rng);
  /// Hex; derived once, on first use: the inbox compares every event against it (the echo check).
  std::string const & Pubkey() const;

  /// The next location; `fix` gives everything but seq.
  nostr::Event LocationEvent(Location fix, crypto::Rng & rng, int64_t now);
  /// The same end whatever the reason (stop, removal, time limit, re-key): a removed recipient must not
  /// learn whether the sharer carries on with others.
  nostr::Event EndEvent(crypto::Rng & rng, int64_t now);

private:
  int64_t NextCreatedAt(int64_t now);

  mutable std::string m_pubkey;
};

/// A location or end of the granted stream, newer than `lastSeq`, or nothing. Any failure discards the
/// event silently (§12).
std::optional<StreamMessage> ReadStream(Share const & grant, nostr::Event const & event, int64_t lastSeq, int64_t now);

/// What a change of the share publishes, in two phases: first the states, then, once each state has an
/// OK from at least one relay (or kOkWait has passed), the old stream's end.
struct Rekey
{
  std::vector<std::pair<ContactPtr, nostr::Event>> m_states;
  std::optional<nostr::Event> m_end;
};

/// The recipients of a share, in the order the user picked them, with their `until` (0: until stopped).
using Grants = std::vector<std::pair<ContactPtr, int64_t>>;

/// The sharer's side of §9: one stream for all current recipients, replaced whenever anyone is added or
/// removed (including by `until`) and at every new epoch. Nothing here is written to disk.
class Sharer
{
public:
  /// Throws std::invalid_argument for an invalid relay list.
  explicit Sharer(Relays relays);

  /// The relays the states name, from the next state on. Throws std::invalid_argument for an invalid list.
  void SetRelays(Relays relays);
  /// The dot colour the states carry, from the next state on (§8).
  void SetColor(std::optional<std::string> color) { m_color = std::move(color); }

  bool IsSharing() const { return m_stream.has_value(); }
  Grants const & GetGrants() const { return m_grants; }
  Stream const * GetStream() const { return m_stream ? &*m_stream : nullptr; }
  int64_t NotBefore() const { return m_notBefore; }
  /// The epoch in which the current stream was created: its events travel in that epoch's scope (spec §11).
  int64_t StreamEpoch() const { return m_streamEpoch; }

  /// Throws std::logic_error when already sharing.
  Rekey Start(Grants grants, crypto::Rng & rng, int64_t now);
  /// A new recipient set (or the same one at a new epoch): every state (new grants and share-less ones,
  /// shuffled), then the old stream's end. The new stream stays silent until NotBefore().
  Rekey Change(Grants grants, crypto::Rng & rng, int64_t now);
  /// A new `until` for a CURRENT recipient, earlier or later: same stream, no re-key (once the new `until`
  /// passes, Tick() re-keys without the recipient). Adding someone goes through Change(),
  /// so that a newcomer cannot read what was published before it was granted. Throws
  /// std::invalid_argument for anyone else, or for an `until` in the past.
  nostr::Event Extend(ContactPtr const & contact, int64_t until, crypto::Rng & rng, int64_t now);
  /// This device's current state towards `contact`, sent again, e.g. as the joiner's daily confirmation
  /// (§6.3): with the grant while `contact` is a recipient, so that sending it never ends a share.
  nostr::Event CurrentState(ContactPtr const & contact, crypto::Rng & rng, int64_t now);
  /// Same shape as Change() seen from a removed recipient: states (shuffled), then the end.
  Rekey Stop(crypto::Rng & rng, int64_t now);
  /// Time limits and the epoch change.
  std::optional<Rekey> Tick(crypto::Rng & rng, int64_t now);
  /// The next location, or nothing while not sharing or during the silence of a new stream.
  std::optional<nostr::Event> PublishLocation(Location const & fix, crypto::Rng & rng, int64_t now);

private:
  std::optional<int64_t> UntilOf(ContactPtr const & contact) const;
  std::vector<std::pair<ContactPtr, nostr::Event>> States(std::vector<ContactPtr> const & removed, crypto::Rng & rng,
                                                          int64_t now);

  Relays m_relays;
  std::optional<std::string> m_color;
  Grants m_grants;
  std::optional<Stream> m_stream;
  int64_t m_streamEpoch = 0;
  int64_t m_notBefore = 0;
};

/// The viewer's side of one contact's share: the current grant and the latest position, in memory only.
/// A replaced or ended stream key is dropped at once (§12). The last position survives an end, marked
/// stale, for kEndGrace: states and the end travel over different relays, so the end can arrive before
/// the grant of its replacement.
class Following
{
public:
  void OnState(State const & state, int64_t now);
  /// The accepted location or end, or nothing.
  std::optional<StreamMessage> OnStream(nostr::Event const & event, int64_t now);
  void Tick(int64_t now);
  void Stop();

  std::optional<Share> const & Grant() const { return m_grant; }
  std::optional<Location> const & Position() const { return m_position; }
  bool IsStale() const { return m_stale; }

private:
  std::optional<Share> m_grant;
  int64_t m_lastSeq = 0;
  std::optional<Location> m_position;
  bool m_stale = false;
  std::optional<int64_t> m_endedAt;
};
}  // namespace live_location
