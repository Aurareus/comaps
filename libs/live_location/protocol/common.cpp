#include "live_location/protocol/common.hpp"

#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/nip44.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/protocol/constants.hpp"
#include "live_location/protocol/messages.hpp"

#include <stdexcept>

namespace live_location
{
Bytes Label(std::string_view purpose)
{
  return Concat({AsBytes("nll1:"), AsBytes(purpose)});
}

int64_t EpochOf(int64_t unixTime)
{
  // Floor division, like Python's //.
  int64_t const q = unixTime / kEpochSeconds;
  return (unixTime % kEpochSeconds < 0) ? q - 1 : q;
}

int64_t EpochEnd(int64_t epoch)
{
  return (epoch + 1) * kEpochSeconds;
}

Key DeriveSecpKey(ByteSpan prk, std::string_view purpose)
{
  Bytes info = Label(purpose);
  info.push_back(0);
  for (unsigned ctr = 0; ctr < 256; ++ctr)
  {
    info.back() = static_cast<uint8_t>(ctr);
    auto candidate = crypto::HkdfExpandTo<32>(prk, info);
    if (crypto::IsValidSecretKey(candidate))
      return Key(candidate);
  }
  throw std::runtime_error("no valid secp256k1 key");  // probability about 2^-32768
}

Key RandomSecpKey(crypto::Rng & rng)
{
  while (true)
  {
    auto candidate = rng.Get<32>();
    if (crypto::IsValidSecretKey(candidate))
      return Key(candidate);
  }
}

uint32_t RandomBelow(crypto::Rng & rng, uint32_t n)
{
  ByteArray<4> b;
  rng.Fill(b.data(), b.size());
  uint32_t const v = uint32_t{b[0]} << 24 | uint32_t{b[1]} << 16 | uint32_t{b[2]} << 8 | b[3];
  return v % n;
}

std::string Seal(json::Value const & message, size_t size, Key const & conversationKey, crypto::Rng & rng)
{
  auto const plaintext = EncodePlaintext(message, size);
  ByteArray<32> nonce;
  rng.Fill(nonce.data(), nonce.size());
  return nip44::Encrypt(plaintext, conversationKey, nonce);
}

std::optional<json::Value> OpenSealed(std::string_view content, Key const & conversationKey)
{
  auto const plaintext = nip44::Decrypt(content, conversationKey);
  if (!plaintext)
    return {};
  return DecodePlaintext(*plaintext);
}

nostr::Event SignEvent(Key const & secretKey, int64_t createdAt, int64_t kind, nostr::Tags tags, std::string content,
                       crypto::Rng & rng)
{
  nostr::Event event;
  event.m_createdAt = createdAt;
  event.m_kind = kind;
  event.m_tags = std::move(tags);
  event.m_content = std::move(content);
  ByteArray<32> aux;
  rng.Fill(aux.data(), aux.size());
  nostr::Sign(event, secretKey, aux);
  return event;
}

bool CheckEvent(nostr::Event const & event, std::set<std::string> const * expectedPubkeys, int64_t kind,
                std::optional<std::string_view> d, int64_t now, std::optional<std::string_view> pTag)
{
  if (event.m_createdAt < 0 || event.m_kind != kind)
    return false;
  if (expectedPubkeys != nullptr && expectedPubkeys->count(event.m_pubkey) == 0)
    return false;
  if (!nostr::Verify(event))
    return false;
  if (event.m_createdAt > now + kMaxFutureSkew)
    return false;
  if (d && event.TagValue("d") != std::string(*d))
    return false;
  if (pTag && event.TagValue("p") != std::string(*pTag))
    return false;
  if (kind == kKindStored)
  {
    auto const exp = event.TagValue("expiration");
    if (!exp || exp->empty() || exp->size() > 10)
      return false;
    int64_t value = 0;
    for (char const c : *exp)
    {
      if (c < '0' || c > '9')
        return false;
      value = value * 10 + (c - '0');
    }
    if (value <= now)
      return false;
  }
  return true;
}
}  // namespace live_location
