#include "live_location/crypto/nip44.hpp"

#include "live_location/crypto/chacha.hpp"
#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/encoding/base64.hpp"

#include <stdexcept>

namespace live_location::nip44
{
namespace
{
uint8_t constexpr kVersion = 2;
size_t constexpr kNonceSize = 32;
size_t constexpr kMacSize = 32;
size_t constexpr kMinPayloadChars = 132;
size_t constexpr kMaxPayloadChars = 87472;
size_t constexpr kMinDataSize = 99;

Key Mac(Key const & hmacKey, ByteSpan nonce, ByteSpan ciphertext)
{
  return crypto::HmacSha256Concat(hmacKey, {nonce, ciphertext});
}
}  // namespace

MessageKeys GetMessageKeys(Key const & conversationKey, ByteArray<32> const & nonce)
{
  auto const keys = crypto::HkdfExpand(conversationKey, nonce, 76);
  MessageKeys out;
  std::copy_n(keys.begin(), 32, out.m_chachaKey.begin());
  std::copy_n(keys.begin() + 32, 12, out.m_chachaNonce.begin());
  std::copy_n(keys.begin() + 44, 32, out.m_hmacKey.begin());
  return out;
}

size_t CalcPaddedLen(size_t unpaddedSize)
{
  if (unpaddedSize == 0)
    throw std::invalid_argument("NIP-44: empty plaintext");
  if (unpaddedSize <= 32)
    return 32;
  size_t nextPower = 1;
  while (nextPower < unpaddedSize)
    nextPower <<= 1;
  size_t const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * ((unpaddedSize - 1) / chunk + 1);
}

std::string Encrypt(ByteSpan plaintext, Key const & conversationKey, ByteArray<32> const & nonce)
{
  if (plaintext.empty() || plaintext.size() > kMaxPlaintextSize)
    throw std::invalid_argument("NIP-44: plaintext size outside the NLL profile");

  SecretBytes padded(2 + CalcPaddedLen(plaintext.size()));
  padded[0] = static_cast<uint8_t>(plaintext.size() >> 8);
  padded[1] = static_cast<uint8_t>(plaintext.size());
  std::copy(plaintext.begin(), plaintext.end(), padded.begin() + 2);

  auto const keys = GetMessageKeys(conversationKey, nonce);
  Bytes const ciphertext = crypto::ChaCha20(keys.m_chachaKey, keys.m_chachaNonce, padded);
  Key const mac = Mac(keys.m_hmacKey, nonce, ciphertext);
  uint8_t const version = kVersion;
  return Base64Encode(Concat({ByteSpan(&version, 1), nonce, ciphertext, mac}));
}

std::optional<SecretBytes> Decrypt(std::string_view payload, Key const & conversationKey)
{
  if (payload.empty() || payload.front() == '#')
    return {};  // a future version
  if (payload.size() < kMinPayloadChars || payload.size() > kMaxPayloadChars)
    return {};
  auto const data = Base64Decode(payload);
  if (!data || data->size() < kMinDataSize || (*data)[0] != kVersion)
    return {};

  ByteArray<32> nonce;
  std::copy_n(data->begin() + 1, kNonceSize, nonce.begin());
  ByteSpan const ciphertext(data->data() + 1 + kNonceSize, data->size() - 1 - kNonceSize - kMacSize);
  ByteSpan const mac(data->data() + data->size() - kMacSize, kMacSize);

  auto const keys = GetMessageKeys(conversationKey, nonce);
  if (!ConstantTimeEqual(Mac(keys.m_hmacKey, nonce, ciphertext), mac))
    return {};

  SecretBytes padded(ciphertext.size());
  crypto::ChaCha20Into(keys.m_chachaKey, keys.m_chachaNonce, ciphertext, padded);
  size_t const size = size_t{padded[0]} << 8 | padded[1];
  // Size 0 would announce the extended prefix, which the profile does not allow.
  if (size == 0 || padded.size() != 2 + CalcPaddedLen(size))
    return {};
  return SecretBytes(ByteSpan(padded.data() + 2, size));
}
}  // namespace live_location::nip44
