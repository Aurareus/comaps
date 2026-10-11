#include "live_location/protocol/pairing.hpp"

#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/crypto/x25519.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"

namespace live_location
{
ByteArray<32> Commitment(ByteSpan ePublic)
{
  return crypto::Sha256Concat({Label("commit"), ePublic});
}

Key ConfirmKey(Key const & k1)
{
  return crypto::HkdfExpandTo<32>(k1, Label("pair3"));
}

std::string Step0Content(Key const & macKey, ByteSpan jpk, ByteSpan c)
{
  Key const tag = crypto::HmacSha256Concat(macKey, {jpk, c});
  return Base64Encode(Concat({c, tag}));
}

std::optional<ByteArray<32>> Step0Commitment(nostr::Event const & event, Key const & macKey)
{
  auto const data = Base64Decode(event.m_content);
  auto const jpk = FromHexArray<32>(event.m_pubkey);
  if (!data || data->size() != 64 || !jpk)
    return {};
  ByteSpan const c(data->data(), 32);
  ByteSpan const tag(data->data() + 32, 32);
  if (!ConstantTimeEqual(tag, crypto::HmacSha256Concat(macKey, {*jpk, c})))
    return {};
  ByteArray<32> out;
  std::copy(c.begin(), c.end(), out.begin());
  return out;
}

nostr::Event PairingEvent(Key const & secretKey, int step, Invite const & invite, std::string content,
                          crypto::Rng & rng, int64_t now)
{
  nostr::Tags tags = {{"d", std::to_string(step)}};
  if (step == 0 || step == 2)
    tags.push_back({"p", ToHex(invite.m_ipk)});
  tags.push_back({"expiration", std::to_string(invite.m_expiresAt)});
  return SignEvent(secretKey, now, kKindStored, std::move(tags), std::move(content), rng);
}

std::optional<int> PairingStep(nostr::Event const & event, Invite const & invite, int64_t now)
{
  if (now >= invite.m_expiresAt)
    return {};
  auto const d = event.TagValue("d");
  if (!d)
    return {};
  std::string const ipk = ToHex(invite.m_ipk);
  bool ok = false;
  if (*d == "1" || *d == "3")
  {
    std::set<std::string> const inviter = {ipk};
    ok = CheckEvent(event, &inviter, kKindStored, *d, now);
  }
  else if (*d == "0" || *d == "2")
  {
    ok = CheckEvent(event, nullptr, kKindStored, *d, now, ipk);
  }
  if (!ok)
    return {};
  return (*d)[0] - '0';
}

// --- Joiner ---------------------------------------------------------------------------------

Joiner::Joiner(Invite invite, std::string name, Relays relays, crypto::Rng & rng, int64_t now)
  : m_invite(std::move(invite))
  , m_name(std::move(name))
  , m_relays(std::move(relays))
{
  if (now >= m_invite.m_expiresAt)
    throw std::invalid_argument("invite expired");
  if (m_invite.m_expiresAt > now + kMaxInviteLifetime + kMaxFutureSkew)
    throw std::invalid_argument("invite lifetime over a day: it would keep this phone watching its relays");
  if (!IsValidName(m_name) || !IsValidRelayList(m_relays))
    throw std::invalid_argument("invalid name or relay list");
  m_macKey = m_invite.MacKey();
  m_jsk = RandomSecpKey(rng);  // signs steps 0 and 2
  m_jpk = crypto::GetXOnlyPublicKey(*m_jsk);
  m_e = rng.Get<32>();  // used in exactly one step 2, never again
  m_c = Commitment(crypto::X25519PublicKey(*m_e));
  m_hs = std::make_unique<noise::HandshakeState>(false /* initiator */, m_invite.Prologue(m_jpk, m_c), *m_invite.m_psk,
                                                 *m_e);
}

nostr::Event const & Joiner::CommitEvent(crypto::Rng & rng, int64_t now)
{
  if (!m_step0)
  {
    if (!m_jsk)
      throw std::logic_error("aborted");
    m_step0 = PairingEvent(*m_jsk, 0, m_invite, Step0Content(*m_macKey, m_jpk, m_c), rng, now);
  }
  return *m_step0;
}

Outcome Joiner::Conflict(char const * why)
{
  if (!m_done)
  {
    Abort();
    throw PairingAborted(why);
  }
  if (m_contact)
    m_contact->m_flagged = true;
  Outcome out;
  out.m_flagged = true;
  return out;
}

std::optional<Outcome> Joiner::OnEvent(nostr::Event const & event, crypto::Rng & rng, int64_t now)
{
  if (!m_macKey)
    return {};  // aborted or expired
  auto const step = PairingStep(event, m_invite, now);
  if (!step)
    return {};
  if (*step == 0 || *step == 2)
  {
    if (event.m_pubkey == ToHex(m_jpk))
      return {};  // our own: nobody else can sign them
    if (*step == 0 && Step0Commitment(event, *m_macKey))
      return Conflict("another device used this invite");
    return {};  // no proof of the PSK: not evidence of anything
  }
  auto const prev = m_accepted.find(*step);
  if (prev != m_accepted.end())
  {
    if (prev->second == event.m_id)
      return {};
    return Conflict(*step == 1 ? "the inviter sent a second step 1" : "the inviter sent a second step 3");
  }
  if (m_done)
    return {};

  if (*step == 1)
  {
    m_accepted[1] = event.m_id;
    std::optional<Bytes> message2;
    if (auto const data = Base64Decode(event.m_content))
    {
      auto const payload = m_hs->ReadMessage(*data);
      auto const info = payload ? DecodePlaintext(*payload) : std::nullopt;
      if (info && MessageType(*info) == "pair1")
      {
        // Writing step 2 computes ee, which fails on a low-order key in step 1: that must abort like any
        // other invalid step 1.
        Pair2 const pair2{m_name, m_relays};
        message2 = m_hs->WriteMessage(EncodePlaintext(ToJson(pair2), kSizeControl));
      }
    }
    if (!message2)
      return Conflict("the inviter answered someone else, or step 1 is invalid");
    m_step2 = PairingEvent(*m_jsk, 2, m_invite, Base64Encode(*message2), rng, now);
    auto const split = m_hs->Split();
    m_k1 = split.m_k1;
    m_k2 = split.m_k2;
    m_handshakeHash = m_hs->HandshakeHash();
    m_hs.reset();
    m_e.reset();
    m_sas = SasDigits(*m_k1);
    Outcome out;
    out.m_publish = m_step2;
    out.m_showCode = ShowCode{m_sas, {}, {}};
    return out;
  }

  if (!m_step2)
    throw PairingOutOfOrder("step 3 before step 2 was sent");  // keep it for later (§6.3)
  m_accepted[3] = event.m_id;
  auto const body = OpenSealed(event.m_content, ConfirmKey(*m_k1));
  auto const pair3 = body ? ParsePair3(*body) : std::nullopt;
  int64_t const epoch = EpochOf(now);
  if (!pair3 || (pair3->m_ok && (pair3->m_epoch < epoch - 1 || pair3->m_epoch > epoch)))
    return Conflict("invalid step 3");

  ContactPtr contact;
  if (pair3->m_ok)
  {
    int64_t const ep = pair3->m_epoch;
    contact = std::make_shared<Contact>(pair3->m_name, pair3->m_relays, Direction::FromRoot(*m_k2, ep),
                                        Direction::FromRoot(*m_k1, ep), m_sas);
    contact->m_pairingEpoch = ep;
    contact->m_joiner = true;
  }
  m_done = true;
  EraseSecrets();
  Outcome out;
  if (!pair3->m_ok)
  {
    out.m_declined = true;
    return out;
  }
  m_contact = contact;
  // Completion has to be two-sided: the inviter's contact exists from its decision on, but only a
  // message on the new channel tells it that the joiner got step 3. This state is the first such
  // message; ConfirmationDue() asks for one a day through epoch e_p + 7 (§6.3).
  out.m_contact = contact;
  out.m_publish = StateEvent(*contact, m_relays, std::nullopt, rng, now);
  return out;
}

void Joiner::EraseSecrets()
{
  // Until the invite expires, keep only what watching for conflicts needs: the MAC key and public data.
  // The roots go too: whoever holds them can derive every chain key.
  m_invite.m_psk.reset();
  m_jsk.reset();
  m_e.reset();
  m_hs.reset();
  m_k1.reset();
  m_k2.reset();
}

void Joiner::Abort()
{
  EraseSecrets();
  m_macKey.reset();
}

bool Joiner::HasSecrets() const
{
  return m_invite.m_psk || m_jsk || m_e || m_hs || m_k1 || m_k2;
}

// --- Inviter --------------------------------------------------------------------------------

Inviter::Inviter(Relays relays, crypto::Rng & rng, int64_t now, int64_t lifetime)
{
  if (lifetime <= 0 || lifetime > kMaxInviteLifetime)
    throw std::invalid_argument("invite lifetime must be at most a day");
  if (!IsValidRelayList(relays))
    throw std::invalid_argument("invalid relay list");
  Key const psk = rng.Get<32>();
  m_isk = RandomSecpKey(rng);  // signs steps 1 and 3; its public key goes into the invite
  m_invite.m_psk = psk;
  m_invite.m_ipk = crypto::GetXOnlyPublicKey(*m_isk);
  m_invite.m_expiresAt = now + lifetime;
  m_invite.m_relays = std::move(relays);
  m_macKey = m_invite.MacKey();
  m_e = rng.Get<32>();
}

Outcome Inviter::Conflict(char const * why)
{
  if (!m_decided)
  {
    Abort();
    throw PairingAborted(why);
  }
  if (m_contact)
    m_contact->m_flagged = true;
  Outcome out;
  out.m_flagged = true;
  return out;
}

std::optional<Outcome> Inviter::OnEvent(nostr::Event const & event, crypto::Rng & rng, int64_t now)
{
  if (!m_macKey)
    return {};  // aborted or expired
  auto const step = PairingStep(event, m_invite, now);
  if (!step || (*step != 0 && *step != 2))
    return {};

  if (*step == 0)
  {
    auto const c = Step0Commitment(event, *m_macKey);
    auto const accepted = m_accepted.find(0);
    if (!c || (accepted != m_accepted.end() && accepted->second == event.m_id))
      return {};
    if (accepted != m_accepted.end() || m_decided)
      return Conflict("another device used this invite");
    m_accepted[0] = event.m_id;
    m_jpk = FromHexArray<32>(event.m_pubkey);
    m_commit = *c;
    m_hs = std::make_unique<noise::HandshakeState>(true /* initiator */, m_invite.Prologue(*m_jpk, *c), *m_invite.m_psk,
                                                   *m_e);
    auto const message1 = m_hs->WriteMessage(EncodePlaintext(Pair1Json(), kSizeControl));
    Outcome out;
    out.m_publish = PairingEvent(*m_isk, 1, m_invite, Base64Encode(*message1), rng, now);
    return out;
  }

  if (!m_jpk || event.m_pubkey != ToHex(*m_jpk))
    return {};  // only the accepted joiner's step 2 counts
  auto const prev = m_accepted.find(2);
  if (prev != m_accepted.end())
  {
    if (prev->second == event.m_id)
      return {};
    return Conflict("a second, different step 2");
  }
  m_accepted[2] = event.m_id;

  std::optional<Pair2> info;
  auto const data = Base64Decode(event.m_content);
  if (data && data->size() >= noise::kDhLen &&
      ConstantTimeEqual(Commitment(ByteSpan(data->data(), noise::kDhLen)), m_commit))
  {
    auto const payload = m_hs->ReadMessage(*data);
    auto const message = payload ? DecodePlaintext(*payload) : std::nullopt;
    if (message)
      info = ParsePair2(*message);
  }
  if (!info)
    return Conflict("invalid step 2");

  auto const split = m_hs->Split();
  m_k1 = split.m_k1;
  m_k2 = split.m_k2;
  m_handshakeHash = m_hs->HandshakeHash();
  m_hs.reset();
  m_e.reset();
  m_request = info;
  m_sas = SasDigits(*m_k1);
  Outcome out;
  out.m_showCode = ShowCode{m_sas, info->m_name, info->m_relays};
  return out;
}

Outcome Inviter::Decide(bool accept, std::string const & name, Relays const & relays, crypto::Rng & rng, int64_t now)
{
  if (!m_request || m_decided || !m_k1)
    throw std::logic_error("out of order or aborted");
  if (now >= m_invite.m_expiresAt)
    throw std::invalid_argument("invite expired: relays would refuse step 3, and the joiner stops at expiry");
  if (accept && (!IsValidName(name) || !IsValidRelayList(relays)))
    throw std::invalid_argument("invalid name or relay list");
  m_decided = true;
  // e_p lags by the accepted clock skew, so that it is never in the joiner's future (§6.3).
  int64_t const ep = EpochOf(now - kMaxFutureSkew);
  Pair3 pair3;
  pair3.m_ok = accept;
  if (accept)
  {
    pair3.m_name = name;
    pair3.m_relays = relays;
    pair3.m_epoch = ep;
  }
  std::string content = Seal(ToJson(pair3), kSizeControl, ConfirmKey(*m_k1), rng);
  Outcome out;
  out.m_publish = PairingEvent(*m_isk, 3, m_invite, std::move(content), rng, now);
  if (accept)
  {
    m_contact = std::make_shared<Contact>(m_request->m_name, m_request->m_relays, Direction::FromRoot(*m_k1, ep),
                                          Direction::FromRoot(*m_k2, ep), m_sas);
    m_contact->m_pairingEpoch = ep;
    m_contact->m_confirmed = false;
  }
  EraseSecrets();
  out.m_contact = m_contact;
  out.m_declined = !accept;
  return out;
}

void Inviter::EraseSecrets()
{
  m_invite.m_psk.reset();
  m_isk.reset();
  m_e.reset();
  m_hs.reset();
  m_k1.reset();
  m_k2.reset();
}

void Inviter::Abort()
{
  EraseSecrets();
  m_macKey.reset();
}

bool Inviter::HasSecrets() const
{
  return m_invite.m_psk || m_isk || m_e || m_hs || m_k1 || m_k2;
}
}  // namespace live_location
