#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/crypto/random.hpp"

#include <optional>
#include <set>
#include <string>

// The encrypted file of design doc §8.5 and §10.4.
namespace live_location::store
{
/// The platform's key store (an Android Keystore AES-256-GCM key) wrapping the file's data key. Each
/// Wrap() makes a new wrapping key, so that deleting the old one makes old copies of the file
/// unreadable.
class KeyWrapper
{
public:
  struct Wrapped
  {
    std::string m_alias;  // the wrapping key's name in the platform key store
    Bytes m_blob;         // the data key, wrapped
  };

  virtual ~KeyWrapper() = default;
  /// Makes a new wrapping key and wraps `dataKey` under it. Nothing on failure.
  virtual std::optional<Wrapped> Wrap(Key const & dataKey) = 0;
  virtual std::optional<Key> Unwrap(Wrapped const & wrapped) = 0;
  /// Deletes every wrapping key but `keep`; all of them when it is empty.
  virtual void DeleteAllExcept(std::string const & keep) = 0;
};

/// One file: "NLLS" || u8 version || alias || wrapped data key || XChaCha20-Poly1305(nonce, mac,
/// contents), the header authenticated as associated data. Written to a temporary file, synced, and
/// renamed over the old one.
class Store
{
public:
  enum class Result
  {
    Loaded,
    Empty,        // no file: nothing stored yet
    Unreadable,   // a file that cannot be decrypted: its wrapping key is gone or failed, or it is damaged
    Unavailable,  // a file that cannot be opened or read now, e.g. without a free file descriptor
  };

  Store(std::string path, KeyWrapper & wrapper, crypto::Rng & rng);

  /// Reads the file. Wrapping keys that no file uses any more (a crash during rotation) are deleted,
  /// but only once the file was read, or when there is no file at all. The caller then passes the
  /// secret digests of what it read to SetBaseline().
  Result Load(SecretBytes & contents);
  /// The secrets in the file as loaded, so that the next Save() can tell whether one was erased.
  void SetBaseline(std::set<ByteArray<32>> digests) { m_digests = std::move(digests); }
  /// Writes `contents`. When one of `secretDigests` of the previous write is missing from this one, a
  /// secret was erased: the file is written under a new data key and a new wrapping key, and the old
  /// wrapping key is deleted once the new file is in place. False on failure; the old file stays.
  bool Save(ByteSpan contents, std::set<ByteArray<32>> const & secretDigests);
  /// Deletes the file and every wrapping key.
  void Erase();

  /// For tests: whether the last Save() rotated the keys.
  bool LastSaveRotated() const { return m_lastRotated; }

private:
  bool Write(ByteSpan contents, Key const & dataKey, KeyWrapper::Wrapped const & wrapped);

  std::string m_path;
  KeyWrapper & m_wrapper;
  crypto::Rng & m_rng;
  std::optional<Key> m_dataKey;
  std::optional<KeyWrapper::Wrapped> m_wrapped;
  std::set<ByteArray<32>> m_digests;
  bool m_lastRotated = false;
};

/// A KeyWrapper without a platform key store: the "wrapped" key is the key itself. Only for tests and
/// the desktop test peer; it protects nothing.
class InsecureKeyWrapper : public KeyWrapper
{
public:
  std::optional<Wrapped> Wrap(Key const & dataKey) override;
  std::optional<Key> Unwrap(Wrapped const & wrapped) override;
  void DeleteAllExcept(std::string const & keep) override;

  std::set<std::string> const & Aliases() const { return m_aliases; }

private:
  uint64_t m_next = 1;
  std::set<std::string> m_aliases;
};
}  // namespace live_location::store
