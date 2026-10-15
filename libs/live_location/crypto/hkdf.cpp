#include "live_location/crypto/hkdf.hpp"

#include "live_location/crypto/sha256.hpp"

#include <stdexcept>

namespace live_location::crypto
{
Key HkdfExtract(ByteSpan salt, ByteSpan ikm)
{
  return HmacSha256(salt, ikm);
}

SecretBytes HkdfExpand(ByteSpan prk, ByteSpan info, size_t length)
{
  if (prk.size() < 32)
    throw std::invalid_argument("HKDF-Expand: prk too short");
  if (length > 255 * 32)
    throw std::invalid_argument("HKDF-Expand: length too large");

  SecretBytes out(length);
  Key block;
  size_t blockSize = 0;
  for (size_t offset = 0, counter = 1; offset < length; offset += 32, ++counter)
  {
    uint8_t const c = static_cast<uint8_t>(counter);
    block = HmacSha256Concat(prk, {ByteSpan(block.data(), blockSize), info, ByteSpan(&c, 1)});
    blockSize = block.size();
    std::copy_n(block.begin(), std::min<size_t>(32, length - offset), out.begin() + offset);
  }
  return out;
}
}  // namespace live_location::crypto
