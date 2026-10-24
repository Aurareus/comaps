#include "live_location/crypto/schnorr.hpp"

#include "live_location/crypto/random.hpp"

#include <stdexcept>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

namespace live_location::crypto
{
namespace
{
// One context for the whole process. After creation it is only read, which libsecp256k1 allows from
// several threads at once.
secp256k1_context const * Context()
{
  static secp256k1_context const * const ctx = []
  {
    secp256k1_context * c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    // Blinding against side channels.
    Key seed;
    SystemRng().Fill(seed.data(), seed.size());
    if (secp256k1_context_randomize(c, seed.data()) != 1)
      throw std::runtime_error("secp256k1_context_randomize failed");
    return c;
  }();
  return ctx;
}

class Keypair
{
public:
  explicit Keypair(Key const & secretKey)
  {
    if (secp256k1_keypair_create(Context(), &m_keypair, secretKey.data()) != 1)
      throw std::invalid_argument("invalid secp256k1 secret key");
  }
  ~Keypair() { Wipe(&m_keypair, sizeof(m_keypair)); }

  secp256k1_keypair const & Get() const { return m_keypair; }

private:
  secp256k1_keypair m_keypair;
};
}  // namespace

bool IsValidSecretKey(ByteSpan key)
{
  return key.size() == 32 && secp256k1_ec_seckey_verify(Context(), key.data()) == 1;
}

bool IsValidXOnlyPublicKey(ByteSpan key)
{
  secp256k1_xonly_pubkey parsed;
  return key.size() == 32 && secp256k1_xonly_pubkey_parse(Context(), &parsed, key.data()) == 1;
}

XOnlyPublicKey GetXOnlyPublicKey(Key const & secretKey)
{
  Keypair const keypair(secretKey);
  secp256k1_xonly_pubkey pub;
  if (secp256k1_keypair_xonly_pub(Context(), &pub, nullptr, &keypair.Get()) != 1)
    throw std::runtime_error("secp256k1_keypair_xonly_pub failed");
  XOnlyPublicKey out;
  secp256k1_xonly_pubkey_serialize(Context(), out.data(), &pub);
  return out;
}

Signature SchnorrSign(Key const & secretKey, ByteArray<32> const & message, ByteArray<32> const & auxRandom)
{
  Keypair const keypair(secretKey);
  Signature sig;
  if (secp256k1_schnorrsig_sign32(Context(), sig.data(), message.data(), &keypair.Get(), auxRandom.data()) != 1)
    throw std::runtime_error("secp256k1_schnorrsig_sign32 failed");
  return sig;
}

bool SchnorrVerify(ByteSpan publicKey, ByteSpan message, ByteSpan signature)
{
  if (publicKey.size() != 32 || signature.size() != 64)
    return false;
  secp256k1_xonly_pubkey pub;
  if (secp256k1_xonly_pubkey_parse(Context(), &pub, publicKey.data()) != 1)
    return false;
  return secp256k1_schnorrsig_verify(Context(), signature.data(), message.data(), message.size(), &pub) == 1;
}
}  // namespace live_location::crypto
