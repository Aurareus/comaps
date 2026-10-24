#include "live_location/encoding/base64.hpp"

#include <array>

namespace live_location
{
namespace
{
char constexpr kStandard[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char constexpr kUrlSafe[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string Encode(ByteSpan data, char const * alphabet, bool pad)
{
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= data.size(); i += 3)
  {
    uint32_t const v = uint32_t{data[i]} << 16 | uint32_t{data[i + 1]} << 8 | data[i + 2];
    out += alphabet[v >> 18 & 63];
    out += alphabet[v >> 12 & 63];
    out += alphabet[v >> 6 & 63];
    out += alphabet[v & 63];
  }
  size_t const rest = data.size() - i;
  if (rest == 1)
  {
    uint32_t const v = uint32_t{data[i]} << 16;
    out += alphabet[v >> 18 & 63];
    out += alphabet[v >> 12 & 63];
    if (pad)
      out += "==";
  }
  else if (rest == 2)
  {
    uint32_t const v = uint32_t{data[i]} << 16 | uint32_t{data[i + 1]} << 8;
    out += alphabet[v >> 18 & 63];
    out += alphabet[v >> 12 & 63];
    out += alphabet[v >> 6 & 63];
    if (pad)
      out += '=';
  }
  return out;
}

// Decodes groups of 4 characters (the last one may be 2 or 3 long), then requires that encoding the
// result gives the input back: that rejects non-zero unused bits and anything else non-canonical.
std::optional<Bytes> Decode(std::string_view text, char const * alphabet, bool pad)
{
  std::array<int8_t, 256> values;
  values.fill(-1);
  for (int8_t v = 0; v < 64; ++v)
    values[static_cast<uint8_t>(alphabet[v])] = v;

  std::string_view body = text;
  if (pad)
  {
    if (text.size() % 4 != 0)
      return {};
    if (body.ends_with("=="))
      body.remove_suffix(2);
    else if (body.ends_with('='))
      body.remove_suffix(1);
  }
  if (body.size() % 4 == 1)
    return {};

  Bytes out;
  out.reserve(body.size() / 4 * 3 + 2);
  uint32_t acc = 0;
  int bits = 0;
  for (char const c : body)
  {
    int8_t const v = values[static_cast<uint8_t>(c)];
    if (v < 0)
      return {};
    acc = acc << 6 | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8)
    {
      bits -= 8;
      out.push_back(static_cast<uint8_t>(acc >> bits));
      acc &= (1u << bits) - 1;
    }
  }
  if (Encode(out, alphabet, pad) != text)
    return {};
  return out;
}
}  // namespace

std::string Base64Encode(ByteSpan data)
{
  return Encode(data, kStandard, true /* pad */);
}

std::optional<Bytes> Base64Decode(std::string_view text)
{
  return Decode(text, kStandard, true /* pad */);
}

std::string Base64UrlEncode(ByteSpan data)
{
  return Encode(data, kUrlSafe, false /* pad */);
}

std::optional<Bytes> Base64UrlDecode(std::string_view text)
{
  return Decode(text, kUrlSafe, false /* pad */);
}
}  // namespace live_location
