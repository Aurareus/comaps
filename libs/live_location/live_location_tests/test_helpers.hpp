#pragma once

#include "live_location/crypto/bytes.hpp"

#include <string>
#include <string_view>

namespace live_location_tests
{
/// Lowercase or uppercase hex; fails the test on anything else.
live_location::Bytes Hex(std::string_view hex);
live_location::Key HexKey(std::string_view hex);

template <size_t N>
live_location::ByteArray<N> HexArray(std::string_view hex)
{
  auto const bytes = Hex(hex);
  live_location::ByteArray<N> out{};
  std::copy_n(bytes.begin(), std::min(N, bytes.size()), out.begin());
  return out;
}

/// The whole file, or an empty string if it cannot be read.
std::string ReadFile(std::string const & path);
std::string VectorsPath(std::string const & relative);
}  // namespace live_location_tests
