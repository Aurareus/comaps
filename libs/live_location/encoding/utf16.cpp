#include "live_location/encoding/utf16.hpp"

namespace live_location::encoding
{
std::string Utf16ToUtf8(std::u16string_view utf16)
{
  std::string out;
  out.reserve(utf16.size());
  for (size_t i = 0; i < utf16.size(); ++i)
  {
    char32_t c = utf16[i];
    if (c >= 0xD800 && c <= 0xDBFF && i + 1 < utf16.size() && utf16[i + 1] >= 0xDC00 && utf16[i + 1] <= 0xDFFF)
      c = 0x10000 + ((c - 0xD800) << 10) + (utf16[++i] - 0xDC00);
    else if (c >= 0xD800 && c <= 0xDFFF)
      c = 0xFFFD;

    if (c < 0x80)
    {
      out += static_cast<char>(c);
    }
    else if (c < 0x800)
    {
      out += static_cast<char>(0xC0 | (c >> 6));
      out += static_cast<char>(0x80 | (c & 0x3F));
    }
    else if (c < 0x10000)
    {
      out += static_cast<char>(0xE0 | (c >> 12));
      out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (c & 0x3F));
    }
    else
    {
      out += static_cast<char>(0xF0 | (c >> 18));
      out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (c & 0x3F));
    }
  }
  return out;
}
}  // namespace live_location::encoding
