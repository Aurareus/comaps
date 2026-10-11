#include "testing/testing.hpp"

#include "live_location/live_location_tests/test_helpers.hpp"

#include "live_location/protocol/json.hpp"
#include "live_location/protocol/messages.hpp"

#include "cppjansson/cppjansson.hpp"

#include "base/logging.hpp"

#include <clocale>
#include <string>
#include <utility>
#include <vector>

namespace json_profile_tests
{
using namespace live_location;
using namespace live_location_tests;
using std::length_error;  // TEST_THROW pastes its argument after "std::"

// vectors/profile_cases.json (made by make_profile_cases.py) holds inputs with the verdict of the
// Python reference: hand-written cases for every rule of the profile, and mutations of valid
// plaintexts. Both implementations must agree on every one.
UNIT_TEST(JsonProfile_AgreesWithPythonReference)
{
  base::Json const json(ReadFile(VectorsPath("profile_cases.json")));
  json_t const * cases = base::GetJSONObligatoryField(json.get(), "cases");
  size_t valid = 0;
  for (size_t i = 0; i < json_array_size(cases); ++i)
  {
    json_t const * c = json_array_get(cases, i);
    auto const data = Hex(FromJSONObject<std::string>(c, "hex"));
    bool const expected = json_is_true(base::GetJSONObligatoryField(c, "valid"));
    bool const actual = DecodePlaintext(data).has_value();
    TEST_EQUAL(actual, expected, (FromJSONObject<std::string>(c, "note"), FromJSONObject<std::string>(c, "hex")));
    valid += actual ? 1 : 0;
  }
  TEST_GREATER(json_array_size(cases), 500, ());
  TEST_GREATER(valid, 100, ());
}

std::vector<std::pair<double, std::string>> const kPythonRepr = {
    {0.0, "0.0"},
    {-0.0, "-0.0"},
    {8.0, "8.0"},
    {271.0, "271.0"},
    {52.5200066, "52.5200066"},
    {13.404954, "13.404954"},
    {-122.4194155, "-122.4194155"},
    {0.0001, "0.0001"},
    {1e-05, "1e-05"},
    {0.00012345, "0.00012345"},
    {1e+16, "1e+16"},
    {1000000000000000.0, "1000000000000000.0"},
    {123456.789, "123456.789"},
    {0.1, "0.1"},
    {0.3333333333333333, "0.3333333333333333"},
    {9007199254740992.0, "9007199254740992.0"},
    {1.7976931348623157e+308, "1.7976931348623157e+308"},
    {5e-324, "5e-324"},
    {-1.5e-07, "-1.5e-07"},
    {100.0, "100.0"},
    {1e+22, "1e+22"},
    {1.25e+20, "1.25e+20"},
    {1.2345678901234567e+19, "1.2345678901234567e+19"},
    {0.30000000000000004, "0.30000000000000004"},
    {1234567890123456.8, "1234567890123456.8"},
    {2.5e-05, "2.5e-05"},
    {6.02214076e+23, "6.02214076e+23"},
};

void CheckFormatting(std::string const & what)
{
  for (auto const & [value, repr] : kPythonRepr)
  {
    TEST_EQUAL(json::FormatDouble(value), repr, (what));
    auto const parsed = json::ParseProfile(AsBytes("{\"a\":" + repr + "}"));
    TEST(parsed, (what, repr));
    TEST_EQUAL(parsed->Get("a")->AsNumber(), value, (what, repr));
  }
}

UNIT_TEST(JsonProfile_FormatsDoublesLikePython)
{
  CheckFormatting("C locale");
  // The C library reads and writes the decimal point of the current locale; the output must not depend
  // on it.
  std::string const saved = std::setlocale(LC_NUMERIC, nullptr);
  if (std::setlocale(LC_NUMERIC, "de_DE.UTF-8") != nullptr)
    CheckFormatting("de_DE locale");
  else
    LOG(LWARNING, ("Locale de_DE.UTF-8 not installed; the comma-decimal case is not exercised"));
  std::setlocale(LC_NUMERIC, saved.c_str());
}

UNIT_TEST(JsonProfile_Values)
{
  auto const v =
      json::ParseProfile(AsBytes(R"({"t":"x","nul":"a\u0000b","pair":"🗺","i":-0,"f":-0.5,"big":9007199254740991,)"
                                 R"("o":{"b":true,"n":null},"a":[1,2.5,"s"]})"));
  TEST(v, ());
  TEST_EQUAL(v->Get("nul")->AsString(), std::string("a\0b", 3), ("NUL is kept, with the length"));
  TEST_EQUAL(v->Get("pair")->AsString(), "\xf0\x9f\x97\xba", ());
  TEST(v->Get("i")->IsInt(0, 0), ());
  TEST(!v->Get("f")->IsInt(), ());
  TEST(v->Get("f")->IsNumber(-1, 0), ());
  TEST(v->Get("big")->IsInt(), ());
  TEST(v->Get("o")->Get("b")->IsBool() && v->Get("o")->Get("b")->AsBool(), ());
  TEST(!v->Get("o")->Get("b")->IsNumber(), ("booleans are not numbers"));
  TEST(v->Get("o")->Get("n")->GetType() == json::Value::Type::Null, ());
  TEST(!v->Get("o")->Get("n")->IsNumber(), ());
  TEST_EQUAL(v->Get("a")->Elements().size(), 3, ());
  TEST(v->Get("missing") == nullptr, ());

  // Round trip through Dump(), with the escapes of Python's json.dumps.
  auto obj = json::Value::Object();
  obj.Set("t", json::Value::String("x\"\\\n\x01\x7f\xc3\xa9"));
  TEST_EQUAL(obj.Dump(), "{\"t\":\"x\\\"\\\\\\n\\u0001\x7f\xc3\xa9\"}", ());
  TEST_THROW(EncodePlaintext(obj, 5), length_error, ());
}
}  // namespace json_profile_tests
