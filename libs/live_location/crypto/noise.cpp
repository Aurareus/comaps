#include "live_location/crypto/noise.hpp"

#include "live_location/crypto/chacha.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/crypto/x25519.hpp"
#include "live_location/encoding/binary.hpp"

#include <stdexcept>
#include <string_view>

namespace live_location::noise
{
namespace
{
std::string_view constexpr kProtocolName = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";

struct HkdfOutputs
{
  Key m_out1;
  Key m_out2;
  Key m_out3;
};

// The HKDF of the Noise specification (§4.3), with HMAC-SHA256.
HkdfOutputs NoiseHkdf(Key const & chainingKey, ByteSpan ikm, bool threeOutputs)
{
  Key const tempKey = crypto::HmacSha256(chainingKey, ikm);
  uint8_t const one = 1;
  uint8_t const two = 2;
  uint8_t const three = 3;
  HkdfOutputs out;
  out.m_out1 = crypto::HmacSha256(tempKey, ByteSpan(&one, 1));
  out.m_out2 = crypto::HmacSha256Concat(tempKey, {out.m_out1, ByteSpan(&two, 1)});
  if (threeOutputs)
    out.m_out3 = crypto::HmacSha256Concat(tempKey, {out.m_out2, ByteSpan(&three, 1)});
  return out;
}
}  // namespace

ByteArray<12> CipherState::Nonce() const
{
  ByteArray<12> nonce{};
  for (size_t i = 0; i < 8; ++i)
    nonce[4 + i] = static_cast<uint8_t>(m_n >> (8 * i));
  return nonce;
}

Bytes CipherState::EncryptWithAd(ByteSpan ad, ByteSpan plaintext)
{
  if (!m_hasKey)
    return Bytes(plaintext.begin(), plaintext.end());
  Bytes out = crypto::AeadSeal(m_key, Nonce(), ad, plaintext);
  ++m_n;
  return out;
}

std::optional<SecretBytes> CipherState::DecryptWithAd(ByteSpan ad, ByteSpan ciphertext)
{
  if (!m_hasKey)
    return SecretBytes(ciphertext);
  auto out = crypto::AeadOpen(m_key, Nonce(), ad, ciphertext);
  if (out)
    ++m_n;
  return out;
}

HandshakeState::HandshakeState(bool initiator, ByteSpan prologue, Key const & psk, Key const & ephemeralSecret)
  : m_initiator(initiator)
  , m_psk(psk)
  , m_e(ephemeralSecret)
{
  // The protocol name is longer than HASHLEN, so h starts as its hash.
  m_h = crypto::Sha256(AsBytes(kProtocolName));
  std::copy(m_h.begin(), m_h.end(), m_ck.begin());
  MixHash(prologue);
}

void HandshakeState::MixHash(ByteSpan data)
{
  m_h = crypto::Sha256Concat({m_h, data});
}

void HandshakeState::MixKey(ByteSpan ikm)
{
  auto const out = NoiseHkdf(m_ck, ikm, false /* threeOutputs */);
  m_ck = out.m_out1;
  m_cipher = CipherState(out.m_out2);
}

void HandshakeState::MixKeyAndHash(ByteSpan ikm)
{
  auto const out = NoiseHkdf(m_ck, ikm, true /* threeOutputs */);
  m_ck = out.m_out1;
  MixHash(out.m_out2);
  m_cipher = CipherState(out.m_out3);
}

bool HandshakeState::MixDhEe()
{
  auto const shared = crypto::X25519(m_e, m_re);
  if (!shared)
    return false;
  MixKey(*shared);
  return true;
}

Bytes HandshakeState::EncryptAndHash(ByteSpan plaintext)
{
  Bytes ciphertext = m_cipher.EncryptWithAd(m_h, plaintext);
  MixHash(ciphertext);
  return ciphertext;
}

std::optional<SecretBytes> HandshakeState::DecryptAndHash(ByteSpan ciphertext)
{
  auto plaintext = m_cipher.DecryptWithAd(m_h, ciphertext);
  if (plaintext)
    MixHash(ciphertext);
  return plaintext;
}

// Message 0 is "psk, e" and message 1 is "e, ee". In psk mode, the "e" token also mixes the
// ephemeral key into the chaining key.
std::optional<Bytes> HandshakeState::WriteMessage(ByteSpan payload)
{
  bool const myTurn = (m_messageIndex == 0 && m_initiator) || (m_messageIndex == 1 && !m_initiator);
  if (!myTurn)
    throw std::logic_error("Noise: not this side's turn to write");

  if (m_messageIndex == 0)
    MixKeyAndHash(m_psk);
  auto const ePublic = crypto::X25519PublicKey(m_e);
  MixHash(ePublic);
  MixKey(ePublic);
  if (m_messageIndex == 1 && !MixDhEe())
    return {};
  ++m_messageIndex;
  Bytes out(ePublic.begin(), ePublic.end());
  Bytes const ciphertext = EncryptAndHash(payload);
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  return out;
}

std::optional<SecretBytes> HandshakeState::ReadMessage(ByteSpan message)
{
  bool const peerTurn = (m_messageIndex == 0 && !m_initiator) || (m_messageIndex == 1 && m_initiator);
  if (!peerTurn)
    throw std::logic_error("Noise: not the peer's turn to write");

  if (m_messageIndex == 0)
    MixKeyAndHash(m_psk);
  if (message.size() < kDhLen)
    return {};
  std::copy_n(message.begin(), kDhLen, m_re.begin());
  MixHash(m_re);
  MixKey(m_re);
  if (m_messageIndex == 1 && !MixDhEe())
    return {};
  ++m_messageIndex;
  return DecryptAndHash(message.subspan(kDhLen));
}

HandshakeState::SplitKeys HandshakeState::Split() const
{
  if (!IsComplete())
    throw std::logic_error("Noise: Split() before the handshake is complete");
  auto const out = NoiseHkdf(m_ck, ByteSpan(), false /* threeOutputs */);
  return {out.m_out1, out.m_out2};
}
void CipherState::Save(binary::Writer & writer) const
{
  writer.Secret(m_key);
  writer.Bool(m_hasKey);
  writer.I64(static_cast<int64_t>(m_n));
}

void CipherState::Load(binary::Reader & reader)
{
  m_key = reader.Secret();
  m_hasKey = reader.Bool();
  m_n = static_cast<uint64_t>(reader.I64());
}

void HandshakeState::Save(binary::Writer & writer) const
{
  writer.Bool(m_initiator);
  writer.Secret(m_psk);
  writer.Secret(m_e);
  writer.Raw(m_re);
  writer.Raw(m_h);
  writer.Secret(m_ck);
  m_cipher.Save(writer);
  writer.U8(static_cast<uint8_t>(m_messageIndex));
}

HandshakeState HandshakeState::Load(binary::Reader & reader)
{
  HandshakeState out;
  out.m_initiator = reader.Bool();
  out.m_psk = reader.Secret();
  out.m_e = reader.Secret();
  out.m_re = reader.Array<kDhLen>();
  out.m_h = reader.Array<32>();
  out.m_ck = reader.Secret();
  out.m_cipher.Load(reader);
  out.m_messageIndex = reader.U8();
  if (out.m_messageIndex > 2)
    throw binary::FormatError("Noise message index");
  return out;
}
}  // namespace live_location::noise
