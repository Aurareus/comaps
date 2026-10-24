#pragma once

#include "live_location/crypto/bytes.hpp"

#include <cstdint>

namespace live_location::crypto
{
/// A source of random bytes.
class Rng
{
public:
  virtual ~Rng() = default;
  virtual void Fill(uint8_t * data, size_t size) = 0;

  Bytes GetBytes(size_t size);

  template <size_t N>
  Secret<N> Get()
  {
    Secret<N> out;
    Fill(out.data(), N);
    return out;
  }
};

/// The operating system's CSPRNG. Fill() throws std::runtime_error if it fails.
Rng & SystemRng();

/// Deterministic randomness for tests and vectors, identical to TestRng in
/// tools/python/live_location: output i (from 1) is HKDF-Expand(HKDF-Extract("nll1:test-rng", seed),
/// u64be(i), size).
class TestRng final : public Rng
{
public:
  explicit TestRng(ByteSpan seed);
  void Fill(uint8_t * data, size_t size) override;

private:
  Key m_prk;
  uint64_t m_counter = 0;
};
}  // namespace live_location::crypto
