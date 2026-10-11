#pragma once

#include "live_location/crypto/bytes.hpp"

#include <cstdint>
#include <optional>

namespace live_location::binary
{
class Reader;
class Writer;
}  // namespace live_location::binary

namespace live_location::noise
{
size_t constexpr kDhLen = 32;

/// One direction of transport encryption after Split(). NLL itself uses the raw split keys (spec
/// §6.3); this exists for the published test vectors.
class CipherState
{
public:
  CipherState() = default;
  explicit CipherState(Key const & key) : m_key(key), m_hasKey(true) {}

  bool HasKey() const { return m_hasKey; }
  Bytes EncryptWithAd(ByteSpan ad, ByteSpan plaintext);
  std::optional<SecretBytes> DecryptWithAd(ByteSpan ad, ByteSpan ciphertext);

  void Save(binary::Writer & writer) const;
  void Load(binary::Reader & reader);

private:
  ByteArray<12> Nonce() const;

  Key m_key;
  bool m_hasKey = false;
  uint64_t m_n = 0;
};

/// Noise_NNpsk0_25519_ChaChaPoly_SHA256 (Noise revision 34), the pairing handshake (spec §6.3):
///   -> psk, e
///   <- e, ee
/// A failed step leaves the state unusable: the caller aborts the pairing.
class HandshakeState
{
public:
  HandshakeState(bool initiator, ByteSpan prologue, Key const & psk, Key const & ephemeralSecret);

  /// This side's next message. Nothing if the ee Diffie-Hellman result is all zeros. Throws
  /// std::logic_error when it is the peer's turn.
  std::optional<Bytes> WriteMessage(ByteSpan payload);

  /// The payload of the peer's next message, or nothing if the message is too short, does not
  /// decrypt, or its ee result is all zeros. Throws std::logic_error when it is this side's turn.
  std::optional<SecretBytes> ReadMessage(ByteSpan message);

  bool IsComplete() const { return m_messageIndex == 2; }
  ByteArray<32> const & HandshakeHash() const { return m_h; }

  struct SplitKeys
  {
    Key m_k1;  // initiator -> responder
    Key m_k2;  // responder -> initiator
  };
  /// Noise Split(), returning its raw keys. Only once the handshake is complete.
  SplitKeys Split() const;

  /// The whole state, secrets included, for the store: a pairing may span days of app restarts.
  void Save(binary::Writer & writer) const;
  static HandshakeState Load(binary::Reader & reader);

private:
  HandshakeState() = default;

  void MixHash(ByteSpan data);
  void MixKey(ByteSpan ikm);
  void MixKeyAndHash(ByteSpan ikm);
  bool MixDhEe();
  Bytes EncryptAndHash(ByteSpan plaintext);
  std::optional<SecretBytes> DecryptAndHash(ByteSpan ciphertext);

  bool m_initiator = false;
  Key m_psk;
  Key m_e;
  ByteArray<kDhLen> m_re{};
  ByteArray<32> m_h;
  Key m_ck;
  CipherState m_cipher;
  int m_messageIndex = 0;
};
}  // namespace live_location::noise
