#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/nostr/filter.hpp"
#include "live_location/protocol/messages.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

// Pairwise channels (spec §7), channel states (§8), signals (§10) and subscriptions (§11).
namespace live_location
{
/// One direction of a channel: a forward-only chain of epoch keys. Only the key of the oldest epoch
/// still needed is stored. Advance() replaces it, after which earlier epochs are unrecoverable; At()
/// derives a later epoch without storing it.
class Direction
{
public:
  Direction(int64_t epoch, Key const & chainKey) : m_epoch(epoch), m_chainKey(chainKey) {}

  /// CK(e_p) = HKDF-Expand(root, label("ck") || u32be(e_p), 32).
  static Direction FromRoot(Key const & root, int64_t pairingEpoch);

  int64_t Epoch() const { return m_epoch; }
  Key const & ChainKey() const { return m_chainKey; }

  /// The chain at a later (or the same) epoch. Throws std::invalid_argument for an earlier one: its
  /// keys were ratcheted away.
  Direction At(int64_t epoch) const;
  /// Ratchets the stored key forward to `epoch` (no-op if already there), erasing the old one.
  void Advance(int64_t epoch);

  Key SigningKey() const;
  std::string Pubkey() const;
  Key ConversationKey() const;

private:
  int64_t m_epoch;
  Key m_chainKey;
};

struct Contact
{
  Contact(std::string name, Relays relays, Direction outgoing, Direction incoming, std::string sas)
    : m_name(std::move(name))
    , m_relays(std::move(relays))
    , m_outgoing(std::move(outgoing))
    , m_incoming(std::move(incoming))
    , m_sas(std::move(sas))
  {}

  std::string m_name;
  Relays m_relays;       // the peer's home relays (its inbox and stream outbox), in its order (§11)
  Direction m_outgoing;  // me -> peer
  Direction m_incoming;  // peer -> me
  std::string m_sas;
  int64_t m_pairingEpoch = 0;
  bool m_joiner = false;    // this device joined: it scanned or opened the invite
  int64_t m_lastSeqIn = 0;  // the last state seq accepted from the peer
  int64_t m_seqOut = 0;     // the last state seq sent
  int64_t m_lastCreatedOut = 0;
  bool m_verified = false;  // this device's user confirmed that both screens showed the same code
  bool m_flagged = false;   // someone else used the same invite after this pairing finished (§6.3)
  // The peer is known to hold the contact too. An inviter's contact starts false and turns true with the
  // first state or signal that arrives from the joiner (§6.3). False is a label, not a block: sharing
  // with a joiner that never finished leaks nothing, since nobody else holds the channel keys.
  bool m_confirmed = true;
};

using ContactPtr = std::shared_ptr<Contact>;

/// CK(e) is erased once now >= epoch_end(e) + 3600, in both directions (§7).
void Ratchet(Contact & contact, int64_t now);

/// The 6-digit code "123 456" from the key schedule (§6.4).
std::string SasDigits(Key const & k1);

/// A channel event towards `contact` (kind 30484, d "") carrying `body`; created_at strictly increases.
nostr::Event ControlEvent(Contact & contact, json::Value const & body, crypto::Rng & rng, int64_t now);
/// The next state towards `contact`, with `share` while sharing with it, and the sender's dot colour if any.
nostr::Event StateEvent(Contact & contact, Relays const & relays, std::optional<Share> const & share, crypto::Rng & rng,
                        int64_t now, std::optional<std::string> const & color = {});

/// The keys that may sign the peer's events towards me: epochs e-1..e+1 (clock skew), minus erased
/// ones, by public key.
std::map<std::string, Direction> IncomingKeys(Contact & contact, int64_t now);

/// A state from `contact`, or nothing. Any failure discards the event silently (§12).
std::optional<State> ReadControl(Contact & contact, nostr::Event const & event, int64_t now);

/// Joiner side (§6.3): whether to send the current state to the inviter now. Through epoch e_p + 7, every
/// UTC day on which the joiner runs carries one state. Send the CURRENT state (Sharer::CurrentState): a
/// state without a share would end a share with the inviter.
bool ConfirmationDue(Contact const & contact, int64_t now);
/// Inviter side (§6.3): a contact still waiting once the last state the joiner owed has expired.
bool OfferRemoval(Contact const & contact, int64_t now);

/// Relay consent (§11): (the relays named by a contact that may be used now, those the user must first
/// be asked about). `trusted` holds the user's own relays, the defaults and the approved ones.
std::pair<Relays, Relays> SplitRelays(Relays const & named, std::set<std::string> const & trusted);
/// The relay that live updates need, if the viewer may not use it: the first of the sharer's list,
/// where an unwatched sharer listens (§10, §11).
std::optional<std::string> MissingListeningRelay(Relays const & relays, std::set<std::string> const & trusted);

/// The first `count` decoy public keys of `epoch` (§11), stable for the whole epoch.
std::vector<std::string> DecoyKeys(ByteSpan decoySeed, int64_t epoch, size_t count);
/// The inbox REQ filters: every contact's channel key of ONE epoch, padded with decoys to a multiple of
/// 8 and sorted, for states and signals, at most 50 authors per filter. A contact whose chain is already
/// past `epoch` is left out.
std::vector<nostr::Filter> InboxFilters(std::vector<ContactPtr> const & contacts, ByteSpan decoySeed, int64_t epoch,
                                        int64_t now);

/// A watch signal towards a sharer (§10).
nostr::Event WatchSignal(Contact & contact, int64_t until, crypto::Rng & rng, int64_t now);
/// A watch signal from `contact`, or nothing. It confirms the contact (§6.3).
std::optional<Watch> ReadSignal(Contact & contact, nostr::Event const & event, int64_t now);
}  // namespace live_location
