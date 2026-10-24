#include "testing/testing.hpp"

#include "live_location/encoding/utf16.hpp"

#include "base/string_utils.hpp"

#include <string>

// The Android layer's conversion of Java strings: names may hold any character, emoji included.
namespace utf16_tests
{
using live_location::encoding::Utf16ToUtf8;

UNIT_TEST(Utf16_ToUtf8)
{
  TEST_EQUAL(Utf16ToUtf8(u""), "", ());
  TEST_EQUAL(Utf16ToUtf8(u"Bob"), "Bob", ());
  TEST_EQUAL(Utf16ToUtf8(u"Zoë"), "Zo\xc3\xab", ("two bytes"));
  TEST_EQUAL(Utf16ToUtf8(u"€"), "\xe2\x82\xac", ("three bytes"));
  TEST_EQUAL(Utf16ToUtf8(u"\U0001F600"), "\xf0\x9f\x98\x80", ("a surrogate pair: four bytes, not two times three"));
  TEST_EQUAL(Utf16ToUtf8(u"\U0010FFFF"), "\xf4\x8f\xbf\xbf", ("the last code point"));
}

UNIT_TEST(Utf16_UnpairedSurrogates)
{
  std::string const replacement = "\xef\xbf\xbd";
  TEST_EQUAL(Utf16ToUtf8(std::u16string{0xD83D}), replacement, ("a high surrogate at the end"));
  TEST_EQUAL(Utf16ToUtf8(std::u16string{0xDE00, u'a'}), replacement + "a", ("a lone low surrogate"));
  TEST_EQUAL(Utf16ToUtf8(std::u16string{0xD83D, u'a'}), replacement + "a", ("a high surrogate before a letter"));
  TEST_EQUAL(Utf16ToUtf8(std::u16string{0xD83D, 0xD83D, 0xDE00}), replacement + "\xf0\x9f\x98\x80", ());
}

UNIT_TEST(Utf16_RoundTrip)
{
  // Java to the core and back: the JNI's two directions.
  for (std::string const s :
       {"Alice", "Zo\xc3\xab", "\xe2\x82\xac 5", "\xf0\x9f\x98\x80 Bob \xf0\x9f\x8c\x8d", "\xe4\xb8\xad\xe6\x96\x87"})
    TEST_EQUAL(Utf16ToUtf8(strings::ToUtf16(s)), s, ());
}
}  // namespace utf16_tests
