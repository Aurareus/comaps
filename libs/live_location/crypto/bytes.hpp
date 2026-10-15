#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace live_location
{
using Bytes = std::vector<uint8_t>;
using ByteSpan = std::span<uint8_t const>;

template <size_t N>
using ByteArray = std::array<uint8_t, N>;

/// Overwrites memory in a way that the compiler may not optimise away.
void Wipe(void * data, size_t size);

/// A fixed-size secret, wiped when it is destroyed.
template <size_t N>
class Secret : public std::array<uint8_t, N>
{
public:
  Secret() : std::array<uint8_t, N>{} {}
  explicit Secret(std::array<uint8_t, N> const & bytes) : std::array<uint8_t, N>(bytes) {}
  Secret(Secret const &) = default;
  Secret & operator=(Secret const &) = default;
  ~Secret() { Wipe(this->data(), N); }
};

using Key = Secret<32>;

/// A variable-size secret, wiped when it is destroyed. Size it once: growing it would leave the old
/// buffer behind unwiped.
class SecretBytes : public Bytes
{
public:
  SecretBytes() = default;
  explicit SecretBytes(size_t size) : Bytes(size) {}
  explicit SecretBytes(ByteSpan bytes) : Bytes(bytes.begin(), bytes.end()) {}
  SecretBytes(SecretBytes const &) = default;
  SecretBytes(SecretBytes &&) = default;
  SecretBytes & operator=(SecretBytes const & other);
  SecretBytes & operator=(SecretBytes && other);
  ~SecretBytes() { Wipe(data(), size()); }
};

inline ByteSpan AsBytes(std::string_view s)
{
  return {reinterpret_cast<uint8_t const *>(s.data()), s.size()};
}

Bytes Concat(std::initializer_list<ByteSpan> parts);

/// Compares in constant time for a given length. Buffers of different lengths are unequal.
bool ConstantTimeEqual(ByteSpan a, ByteSpan b);

/// Lowercase hex.
std::string ToHex(ByteSpan data);

/// Strict: an even number of lowercase hex digits and nothing else.
std::optional<Bytes> FromHex(std::string_view hex);

template <size_t N>
std::optional<ByteArray<N>> FromHexArray(std::string_view hex)
{
  if (hex.size() != 2 * N)
    return {};
  auto const bytes = FromHex(hex);
  if (!bytes)
    return {};
  ByteArray<N> out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  return out;
}
}  // namespace live_location
