#pragma once

#include "live_location/crypto/bytes.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>

// The binary encoding of the store (design doc §8.5): big-endian integers, length-prefixed strings,
// written into memory that is wiped.
namespace live_location::binary
{
class FormatError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

class Writer
{
public:
  void U8(uint8_t v);
  void U32(uint32_t v);
  void I64(int64_t v);
  void Bool(bool v) { U8(v ? 1 : 0); }
  /// Bytes of a size the reader knows.
  void Raw(ByteSpan bytes);
  /// A u32 length, then the bytes.
  void Blob(ByteSpan bytes);
  void String(std::string_view s) { Blob(AsBytes(s)); }
  /// A secret key. Its digest is kept, so that the store can tell when a secret has been erased.
  void Secret(Key const & key);
  void OptionalSecret(std::optional<Key> const & key);

  /// The encoding. The working buffer is wiped.
  SecretBytes Finish();
  /// SHA-256 digests of the secrets written.
  std::set<ByteArray<32>> const & SecretDigests() const { return m_digests; }

private:
  void Append(void const * data, size_t size);

  SecretBytes m_buffer;
  size_t m_size = 0;
  std::set<ByteArray<32>> m_digests;
};

/// Reads what Writer wrote. Throws FormatError past the end or for an impossible value.
class Reader
{
public:
  explicit Reader(ByteSpan data) : m_data(data) {}

  uint8_t U8();
  uint32_t U32();
  int64_t I64();
  bool Bool();
  void Raw(uint8_t * out, size_t size);
  template <size_t N>
  std::array<uint8_t, N> Array()
  {
    std::array<uint8_t, N> out;
    Raw(out.data(), N);
    return out;
  }
  Bytes Blob();
  std::string String();
  Key Secret();
  std::optional<Key> OptionalSecret();
  /// A count of items that each take at least `minSize` bytes: refused if the rest cannot hold them.
  uint32_t Count(size_t minSize = 1);

  bool AtEnd() const { return m_offset == m_data.size(); }
  size_t Offset() const { return m_offset; }
  /// Everything not read yet; the reader is then at the end.
  ByteSpan Rest()
  {
    ByteSpan const out = m_data.subspan(m_offset);
    m_offset = m_data.size();
    return out;
  }

private:
  ByteSpan Take(size_t size);

  ByteSpan m_data;
  size_t m_offset = 0;
};
}  // namespace live_location::binary
