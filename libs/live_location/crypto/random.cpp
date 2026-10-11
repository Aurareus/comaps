#include "live_location/crypto/random.hpp"

#include "live_location/crypto/hkdf.hpp"

#include <stdexcept>

#if defined(__APPLE__) || defined(__ANDROID__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <stdlib.h>
#define NLL_RANDOM_ARC4RANDOM
#elif defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#define NLL_RANDOM_GETRANDOM
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#define NLL_RANDOM_BCRYPT
#else
#error "No CSPRNG known for this platform"
#endif

namespace live_location::crypto
{
namespace
{
class OsRng final : public Rng
{
public:
  void Fill(uint8_t * data, size_t size) override
  {
#if defined(NLL_RANDOM_ARC4RANDOM)
    arc4random_buf(data, size);
#elif defined(NLL_RANDOM_GETRANDOM)
    while (size > 0)
    {
      ssize_t const n = getrandom(data, size, 0);
      if (n < 0)
      {
        if (errno == EINTR)
          continue;
        throw std::runtime_error("getrandom failed");
      }
      data += n;
      size -= static_cast<size_t>(n);
    }
#elif defined(NLL_RANDOM_BCRYPT)
    if (BCryptGenRandom(nullptr, data, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
      throw std::runtime_error("BCryptGenRandom failed");
#endif
  }
};
}  // namespace

Bytes Rng::GetBytes(size_t size)
{
  Bytes out(size);
  Fill(out.data(), size);
  return out;
}

Rng & SystemRng()
{
  static OsRng rng;
  return rng;
}

TestRng::TestRng(ByteSpan seed) : m_prk(HkdfExtract(AsBytes("nll1:test-rng"), seed)) {}

void TestRng::Fill(uint8_t * data, size_t size)
{
  ++m_counter;
  ByteArray<8> info;
  for (size_t i = 0; i < 8; ++i)
    info[i] = static_cast<uint8_t>(m_counter >> (8 * (7 - i)));
  auto const out = HkdfExpand(m_prk, info, size);
  std::copy(out.begin(), out.end(), data);
}
}  // namespace live_location::crypto
