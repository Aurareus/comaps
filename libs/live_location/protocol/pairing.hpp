#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/crypto/noise.hpp"
#include "live_location/crypto/random.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/protocol/channel.hpp"
#include "live_location/protocol/invite.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

// Pairing (spec §6.3). Each party signs its own events, so nobody can replace or delete the other's:
//   0  joiner  (jsk)  ["p", ipk]  commitment to the joiner's Noise ephemeral key, MACed with the PSK
//   1  inviter (isk)              Noise NNpsk0 message 1 (psk, e)   payload pair1 (nothing else)
//   2  joiner  (jsk)  ["p", ipk]  Noise NNpsk0 message 2 (e, ee)    payload pair2: name, relays
//   3  inviter (isk)              NIP-44 under the confirm key      payload pair3: ok, name, relays, epoch
namespace live_location::binary
{
class Reader;
class Writer;
}  // namespace live_location::binary

namespace live_location
{
/// How the store names the contact a pairing made: its own ids, not the protocol's.
using ContactIdOf = std::function<std::string(ContactPtr const &)>;
using ContactById = std::function<ContactPtr(std::string const &)>;

/// A pairing step was duplicated or invalid: someone else holds the invite. The pairing has stopped and
/// erased its secrets; tell the user.
class PairingAborted : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

/// A step that depends on one this side has not sent yet: keep the event and offer it again later.
class PairingOutOfOrder : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

struct ShowCode
{
  std::string m_sas;
  std::optional<std::string> m_name;  // the joiner's, shown to the inviter
  std::optional<Relays> m_relays;     // the joiner's, shown to the inviter
};

/// What to do after a pairing event or decision.
struct Outcome
{
  std::optional<nostr::Event> m_publish;  // publish now; a retransmission repeats the same event
  std::optional<ShowCode> m_showCode;     // show the code (the inviter: with the joiner's name, and ask)
  ContactPtr m_contact;                   // the pairing finished with this contact
  bool m_declined = false;                // the inviter declined
  bool m_flagged = false;                 // a conflict after the pairing finished: the contact is flagged
};

/// SHA256(label("commit") || e).
ByteArray<32> Commitment(ByteSpan ePublic);
/// HKDF-Expand(k1, label("pair3"), 32).
Key ConfirmKey(Key const & k1);
/// base64(c || HMAC-SHA256(mac_key, jpk || c)).
std::string Step0Content(Key const & macKey, ByteSpan jpk, ByteSpan c);
/// The commitment of a valid step 0, i.e. one whose author holds the invite; nothing otherwise.
std::optional<ByteArray<32>> Step0Commitment(nostr::Event const & event, Key const & macKey);
/// Joiner steps (0, 2) carry ["p", ipk] so that the inviter finds them; inviter steps do not.
nostr::Event PairingEvent(Key const & secretKey, int step, Invite const & invite, std::string content,
                          crypto::Rng & rng, int64_t now);
/// The step of an envelope-valid pairing event, or nothing. Steps 1 and 3 must be signed by ipk; steps
/// 0 and 2 may come from any key but must carry ["p", ipk]. Nothing once the invite has expired.
std::optional<int> PairingStep(nostr::Event const & event, Invite const & invite, int64_t now);

/// The party that scanned or opened the invite (the Noise responder).
class Joiner
{
public:
  /// Throws std::invalid_argument for an expired invite, one that expires more than a day plus the
  /// accepted skew ahead, or an invalid name or relay list.
  Joiner(Invite invite, std::string name, Relays relays, crypto::Rng & rng, int64_t now);

  /// Step 0, made once: a retransmission resends this same event. Throws std::logic_error once aborted.
  nostr::Event const & CommitEvent(crypto::Rng & rng, int64_t now);

  /// Every event of the two pairing subscriptions, the joiner's own included, until the invite expires.
  /// What to do, or nothing to ignore the event. Throws PairingAborted or PairingOutOfOrder.
  std::optional<Outcome> OnEvent(nostr::Event const & event, crypto::Rng & rng, int64_t now);

  void Abort();
  /// At invite expiry: nothing is left to watch.
  void Expire() { Abort(); }

  Invite const & GetInvite() const { return m_invite; }
  ByteArray<32> const & Jpk() const { return m_jpk; }
  ByteArray<32> const & C() const { return m_c; }
  std::optional<nostr::Event> const & Step0() const { return m_step0; }
  std::optional<nostr::Event> const & Step2() const { return m_step2; }
  std::string const & Sas() const { return m_sas; }
  ContactPtr const & GetContact() const { return m_contact; }
  bool IsAborted() const { return !m_macKey; }
  bool HasSecrets() const;
  /// For vectors and debugging only.
  ByteArray<32> const & HandshakeHash() const { return m_handshakeHash; }
  /// The split keys, present only between step 2 and the end of the pairing.
  std::optional<Key> const & K1() const { return m_k1; }
  std::optional<Key> const & K2() const { return m_k2; }

  /// The whole pairing, secrets included, as the store keeps it (design doc §8.5): a link pairing can
  /// take days of app restarts. Load() throws binary::FormatError.
  void Save(binary::Writer & writer, ContactIdOf const & idOf) const;
  static std::unique_ptr<Joiner> Load(binary::Reader & reader, ContactById const & contactById);

private:
  Joiner() = default;
  Outcome Conflict(char const * why);
  void EraseSecrets();

  Invite m_invite;
  std::string m_name;
  Relays m_relays;
  std::optional<Key> m_macKey;
  std::optional<Key> m_jsk;
  ByteArray<32> m_jpk;
  std::optional<Key> m_e;
  ByteArray<32> m_c;
  std::unique_ptr<noise::HandshakeState> m_hs;
  std::optional<nostr::Event> m_step0;
  std::map<int, std::string> m_accepted;  // step -> id of the one inviter event accepted for it
  std::optional<nostr::Event> m_step2;
  std::optional<Key> m_k1;
  std::optional<Key> m_k2;
  std::string m_sas;
  ContactPtr m_contact;
  bool m_done = false;
  ByteArray<32> m_handshakeHash{};
};

/// The party that showed the invite (the Noise initiator).
class Inviter
{
public:
  /// Throws std::invalid_argument for a lifetime outside (0, 1 day] or an invalid relay list.
  Inviter(Relays relays, crypto::Rng & rng, int64_t now, int64_t lifetime = 600);

  /// Every event of the pairing subscription until the invite expires. Throws PairingAborted.
  std::optional<Outcome> OnEvent(nostr::Event const & event, crypto::Rng & rng, int64_t now);

  /// After the user's decision. Step 3 carries it, with the inviter's name, relays and
  /// e_p = epoch(now - 300). Throws std::logic_error out of order or after an abort, and
  /// std::invalid_argument once the invite has expired or for an invalid name or relay list.
  Outcome Decide(bool accept, std::string const & name, Relays const & relays, crypto::Rng & rng, int64_t now);

  void Abort();
  void Expire() { Abort(); }

  Invite const & GetInvite() const { return m_invite; }
  std::string const & Sas() const { return m_sas; }
  ContactPtr const & GetContact() const { return m_contact; }
  bool IsAborted() const { return !m_macKey; }
  bool HasSecrets() const;
  Key const & PairingSecretForVectors() const { return *m_isk; }
  ByteArray<32> const & HandshakeHash() const { return m_handshakeHash; }
  Key MacKeyForVectors() const { return *m_macKey; }

  /// As Joiner::Save() and Joiner::Load().
  void Save(binary::Writer & writer, ContactIdOf const & idOf) const;
  static std::unique_ptr<Inviter> Load(binary::Reader & reader, ContactById const & contactById);

private:
  Inviter() = default;
  Outcome Conflict(char const * why);
  void EraseSecrets();

  Invite m_invite;
  std::optional<Key> m_isk;
  std::optional<Key> m_macKey;
  std::optional<Key> m_e;
  std::map<int, std::string> m_accepted;  // step -> id of the one joiner event accepted for it
  std::optional<ByteArray<32>> m_jpk;     // author of the accepted step 0
  ByteArray<32> m_commit{};
  std::unique_ptr<noise::HandshakeState> m_hs;
  std::optional<Pair2> m_request;
  std::optional<Key> m_k1;
  std::optional<Key> m_k2;
  std::string m_sas;
  ContactPtr m_contact;
  bool m_decided = false;
  ByteArray<32> m_handshakeHash{};
};
}  // namespace live_location
