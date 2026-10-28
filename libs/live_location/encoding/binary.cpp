#include "live_location/encoding/binary.hpp"

#include "live_location/crypto/sha256.hpp"

#include <cstring>
#include <limits>

namespace live_location::binary
{
void Writer::Append(void const * data, size_t size)
{
  if (m_size + size > m_buffer.size())
  {
    // Grow into a new buffer and wipe the old one: a reallocating vector would leave copies behind.
    SecretBytes bigger(std::max<size_t>(256, 2 * (m_size + size)));
    if (m_size != 0)
      std::memcpy(bigger.data(), m_buffer.data(), m_size);
    m_buffer = std::move(bigger);
  }
  if (size != 0)
    std::memcpy(m_buffer.data() + m_size, data, size);
  m_size += size;
}

void Writer::U8(uint8_t v)
{
  Append(&v, 1);
}

void Writer::U32(uint32_t v)
{
  uint8_t const out[4] = {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8),
                          static_cast<uint8_t>(v)};
  Append(out, sizeof(out));
}

void Writer::I64(int64_t v)
{
  uint64_t const u = static_cast<uint64_t>(v);
  uint8_t out[8];
  for (size_t i = 0; i < 8; ++i)
    out[i] = static_cast<uint8_t>(u >> (56 - 8 * i));
  Append(out, sizeof(out));
}

void Writer::Raw(ByteSpan bytes)
{
  Append(bytes.data(), bytes.size());
}

void Writer::Blob(ByteSpan bytes)
{
  if (bytes.size() > std::numeric_limits<uint32_t>::max())
    throw FormatError("blob too large");
  U32(static_cast<uint32_t>(bytes.size()));
  Raw(bytes);
}

void Writer::Secret(Key const & key)
{
  Raw(key);
  m_digests.insert(crypto::Sha256Concat({AsBytes("nll1:store-digest"), key}));
}

void Writer::OptionalSecret(std::optional<Key> const & key)
{
  Bool(key.has_value());
  if (key)
    Secret(*key);
}

SecretBytes Writer::Finish()
{
  SecretBytes out(ByteSpan(m_buffer.data(), m_size));
  m_buffer = SecretBytes();
  m_size = 0;
  return out;
}

ByteSpan Reader::Take(size_t size)
{
  if (size > m_data.size() - m_offset)
    throw FormatError("truncated");
  ByteSpan const out = m_data.subspan(m_offset, size);
  m_offset += size;
  return out;
}

uint8_t Reader::U8()
{
  return Take(1)[0];
}

uint32_t Reader::U32()
{
  ByteSpan const b = Take(4);
  return (uint32_t{b[0]} << 24) | (uint32_t{b[1]} << 16) | (uint32_t{b[2]} << 8) | uint32_t{b[3]};
}

int64_t Reader::I64()
{
  ByteSpan const b = Take(8);
  uint64_t u = 0;
  for (size_t i = 0; i < 8; ++i)
    u = (u << 8) | b[i];
  return static_cast<int64_t>(u);
}

bool Reader::Bool()
{
  uint8_t const v = U8();
  if (v > 1)
    throw FormatError("not a boolean");
  return v == 1;
}

void Reader::Raw(uint8_t * out, size_t size)
{
  ByteSpan const b = Take(size);
  if (size != 0)
    std::memcpy(out, b.data(), size);
}

Bytes Reader::Blob()
{
  uint32_t const size = U32();
  ByteSpan const b = Take(size);
  return Bytes(b.begin(), b.end());
}

std::string Reader::String()
{
  uint32_t const size = U32();
  ByteSpan const b = Take(size);
  return std::string(b.begin(), b.end());
}

Key Reader::Secret()
{
  Key out;
  Raw(out.data(), out.size());
  return out;
}

std::optional<Key> Reader::OptionalSecret()
{
  if (!Bool())
    return {};
  return Secret();
}

uint32_t Reader::Count(size_t minSize)
{
  uint32_t const n = U32();
  if (minSize != 0 && n > (m_data.size() - m_offset) / minSize)
    throw FormatError("count beyond the data");
  return n;
}
}  // namespace live_location::binary
