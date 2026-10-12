#pragma once

/* SHA-256 and HMAC-SHA256 from libsecp256k1's internal implementation, which the library already
   compiles for BIP-340 (docs/LIVE_LOCATION.md, decision D9). Once CoMaps has Boost >= 1.88, this shim
   can go in favour of boost::hash2::sha2_256 and hmac_sha2_256. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Opaque incremental states, large and aligned enough for libsecp256k1's structs (checked in the .c
   file). */
typedef union
{
  unsigned char opaque[128];
  uint64_t align;
} nll_sha256_ctx;

typedef union
{
  unsigned char opaque[256];
  uint64_t align;
} nll_hmac_sha256_ctx;

void nll_sha256_init(nll_sha256_ctx * ctx);
void nll_sha256_update(nll_sha256_ctx * ctx, unsigned char const * data, size_t size);
/* Writes the digest and wipes the state. */
void nll_sha256_final(nll_sha256_ctx * ctx, unsigned char out32[32]);

void nll_hmac_sha256_init(nll_hmac_sha256_ctx * ctx, unsigned char const * key, size_t keySize);
void nll_hmac_sha256_update(nll_hmac_sha256_ctx * ctx, unsigned char const * data, size_t size);
/* Writes the tag and wipes the state. */
void nll_hmac_sha256_final(nll_hmac_sha256_ctx * ctx, unsigned char out32[32]);

#ifdef __cplusplus
}
#endif
