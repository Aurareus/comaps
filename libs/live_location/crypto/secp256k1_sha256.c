#include "live_location/crypto/secp256k1_sha256.h"

/* libsecp256k1's internal hash implementation (3party/secp256k1/src). Its functions are static, so
   this translation unit gets its own copy of them. */
#include "hash_impl.h"

typedef char nll_sha256_ctx_fits[(sizeof(secp256k1_sha256) <= sizeof(nll_sha256_ctx)) ? 1 : -1];
typedef char nll_hmac_sha256_ctx_fits[(sizeof(secp256k1_hmac_sha256) <= sizeof(nll_hmac_sha256_ctx)) ? 1 : -1];

void nll_sha256_init(nll_sha256_ctx * ctx)
{
  secp256k1_sha256_initialize((secp256k1_sha256 *)ctx);
}

void nll_sha256_update(nll_sha256_ctx * ctx, unsigned char const * data, size_t size)
{
  secp256k1_sha256_write((secp256k1_sha256 *)ctx, data, size);
}

void nll_sha256_final(nll_sha256_ctx * ctx, unsigned char out32[32])
{
  secp256k1_sha256_finalize((secp256k1_sha256 *)ctx, out32);
  secp256k1_sha256_clear((secp256k1_sha256 *)ctx);
}

void nll_hmac_sha256_init(nll_hmac_sha256_ctx * ctx, unsigned char const * key, size_t keySize)
{
  /* An empty key (HKDF's empty salt) may come as a null pointer, which memcpy must not get. */
  static unsigned char const kEmpty[1] = {0};
  secp256k1_hmac_sha256_initialize((secp256k1_hmac_sha256 *)ctx, keySize == 0 ? kEmpty : key, keySize);
}

void nll_hmac_sha256_update(nll_hmac_sha256_ctx * ctx, unsigned char const * data, size_t size)
{
  secp256k1_hmac_sha256_write((secp256k1_hmac_sha256 *)ctx, data, size);
}

void nll_hmac_sha256_final(nll_hmac_sha256_ctx * ctx, unsigned char out32[32])
{
  secp256k1_hmac_sha256_finalize((secp256k1_hmac_sha256 *)ctx, out32);
  secp256k1_hmac_sha256_clear((secp256k1_hmac_sha256 *)ctx);
}
