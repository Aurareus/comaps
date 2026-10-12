#pragma once

#include <string>
#include <string_view>

// Java strings are UTF-16. JNI's own UTF-8 is "modified" (a character beyond U+FFFF as two 3-byte
// sequences), which the core's strict JSON refuses, so the Android layer converts here instead.
namespace live_location::encoding
{
/// UTF-16 as UTF-8. A surrogate without its pair becomes U+FFFD.
std::string Utf16ToUtf8(std::u16string_view utf16);
}  // namespace live_location::encoding
