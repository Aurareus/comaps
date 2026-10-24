#include "live_location/live_location_tests/test_helpers.hpp"

#include "testing/testing.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace live_location_tests
{
using namespace live_location;

Bytes Hex(std::string_view hex)
{
  std::string lower(hex);
  std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return std::tolower(c); });
  auto const bytes = FromHex(lower);
  TEST(bytes, (hex));
  return *bytes;
}

Key HexKey(std::string_view hex)
{
  TEST_EQUAL(hex.size(), 64, (hex));
  return Key(HexArray<32>(hex));
}

std::string ReadFile(std::string const & path)
{
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return {};
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

std::string VectorsPath(std::string const & relative)
{
  return std::string(NLL_VECTORS_DIR) + "/" + relative;
}
}  // namespace live_location_tests
