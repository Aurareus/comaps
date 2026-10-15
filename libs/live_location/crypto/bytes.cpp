#include "live_location/crypto/bytes.hpp"

#include <monocypher.h>

namespace live_location
{
void Wipe(void * data, size_t size)
{
  if (data != nullptr && size != 0)
    crypto_wipe(data, size);
}

SecretBytes & SecretBytes::operator=(SecretBytes const & other)
{
  if (this != &other)
  {
    Wipe(data(), size());
    Bytes::operator=(other);
  }
  return *this;
}

SecretBytes & SecretBytes::operator=(SecretBytes && other)
{
  if (this != &other)
  {
    Wipe(data(), size());
    Bytes::operator=(std::move(other));
  }
  return *this;
}

Bytes Concat(std::initializer_list<ByteSpan> parts)
{
  size_t total = 0;
  for (auto const & part : parts)
    total += part.size();
  Bytes out;
  out.reserve(total);
  for (auto const & part : parts)
    out.insert(out.end(), part.begin(), part.end());
  return out;
}

bool ConstantTimeEqual(ByteSpan a, ByteSpan b)
{
  if (a.size() != b.size())
    return false;
  // volatile keeps the compiler from turning the loop into an early exit.
  uint8_t volatile diff = 0;
  for (size_t i = 0; i < a.size(); ++i)
    diff = diff | (a[i] ^ b[i]);
  return diff == 0;
}

std::string ToHex(ByteSpan data)
{
  static char constexpr kDigits[] = "0123456789abcdef";
  std::string out(2 * data.size(), '\0');
  for (size_t i = 0; i < data.size(); ++i)
  {
    out[2 * i] = kDigits[data[i] >> 4];
    out[2 * i + 1] = kDigits[data[i] & 0x0F];
  }
  return out;
}

std::optional<Bytes> FromHex(std::string_view hex)
{
  if (hex.size() % 2 != 0)
    return {};
  auto const nibble = [](char c)
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    return -1;
  };
  Bytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i)
  {
    int const hi = nibble(hex[2 * i]);
    int const lo = nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return {};
    out[i] = static_cast<uint8_t>(hi << 4 | lo);
  }
  return out;
}
}  // namespace live_location
