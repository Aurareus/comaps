#include "live_location/store/store.hpp"

#include "live_location/encoding/binary.hpp"

#include "base/logging.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <monocypher.h>

namespace live_location::store
{
namespace
{
std::string_view constexpr kMagic = "NLLS";
uint8_t constexpr kVersion = 1;
size_t constexpr kNonceSize = 24;
size_t constexpr kMacSize = 16;

Bytes Header(KeyWrapper::Wrapped const & wrapped)
{
  binary::Writer writer;
  writer.Raw(AsBytes(kMagic));
  writer.U8(kVersion);
  writer.String(wrapped.m_alias);
  writer.Blob(wrapped.m_blob);
  SecretBytes const header = writer.Finish();
  return Bytes(header.begin(), header.end());
}

enum class FileStatus
{
  Read,
  Missing,
  Failed,  // there may be a file, but it could not be opened or read now
};

FileStatus ReadFile(std::string const & path, Bytes & out)
{
  std::FILE * file = std::fopen(path.c_str(), "rb");
  if (file == nullptr)
    return errno == ENOENT ? FileStatus::Missing : FileStatus::Failed;
  uint8_t buffer[4096];
  size_t n;
  while ((n = std::fread(buffer, 1, sizeof(buffer), file)) > 0)
    out.insert(out.end(), buffer, buffer + n);
  bool const ok = std::ferror(file) == 0;
  std::fclose(file);
  return ok ? FileStatus::Read : FileStatus::Failed;
}

void SyncDirectory(std::string const & path)
{
#ifndef _WIN32
  std::string const directory = std::filesystem::path(path).parent_path().string();
  int const fd = ::open(directory.empty() ? "." : directory.c_str(), O_RDONLY);
  if (fd >= 0)
  {
    ::fsync(fd);
    ::close(fd);
  }
#else
  (void)path;
#endif
}

/// A temporary file, synced, then renamed over `path`: a crash leaves the old file or the new one.
bool WriteAtomically(std::string const & path, ByteSpan data)
{
  std::string const temporary = path + ".tmp";
  std::FILE * file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr)
    return false;
  bool ok = std::fwrite(data.data(), 1, data.size(), file) == data.size() && std::fflush(file) == 0;
#ifndef _WIN32
  ok = ok && ::fsync(::fileno(file)) == 0;
#endif
  ok = std::fclose(file) == 0 && ok;
  std::error_code error;
  if (ok)
    std::filesystem::rename(temporary, path, error);
  if (!ok || error)
  {
    std::remove(temporary.c_str());
    return false;
  }
  SyncDirectory(path);
  return true;
}
}  // namespace

Store::Store(std::string path, KeyWrapper & wrapper, crypto::Rng & rng)
  : m_path(std::move(path))
  , m_wrapper(wrapper)
  , m_rng(rng)
{}

Store::Result Store::Load(SecretBytes & contents)
{
  Bytes file;
  switch (ReadFile(m_path, file))
  {
  case FileStatus::Missing:
    // Nothing stored: wrapping keys left over are of no use.
    m_wrapper.DeleteAllExcept("");
    return Result::Empty;
  case FileStatus::Failed:
    LOG(LWARNING, ("Live location: the store could not be read now"));
    return Result::Unavailable;  // keep everything: it may read next time
  case FileStatus::Read: break;
  }
  try
  {
    binary::Reader reader(file);
    char magic[4];
    reader.Raw(reinterpret_cast<uint8_t *>(magic), sizeof(magic));
    if (std::string_view(magic, sizeof(magic)) != kMagic || reader.U8() != kVersion)
      return Result::Unreadable;
    KeyWrapper::Wrapped wrapped;
    wrapped.m_alias = reader.String();
    wrapped.m_blob = reader.Blob();
    size_t const headerSize = reader.Offset();
    auto const nonce = reader.Array<kNonceSize>();
    auto const mac = reader.Array<kMacSize>();
    ByteSpan const cipher = reader.Rest();

    auto const dataKey = m_wrapper.Unwrap(wrapped);
    if (!dataKey)
      return Result::Unreadable;
    SecretBytes plain(cipher.size());
    if (crypto_aead_unlock(plain.data(), mac.data(), dataKey->data(), nonce.data(), file.data(), headerSize,
                           cipher.data(), cipher.size()) != 0)
    {
      return Result::Unreadable;
    }
    contents = std::move(plain);
    m_dataKey = *dataKey;
    m_wrapped = std::move(wrapped);
    m_wrapper.DeleteAllExcept(m_wrapped->m_alias);
    return Result::Loaded;
  }
  catch (binary::FormatError const &)
  {
    return Result::Unreadable;
  }
}

bool Store::Write(ByteSpan contents, Key const & dataKey, KeyWrapper::Wrapped const & wrapped)
{
  Bytes file = Header(wrapped);
  size_t const headerSize = file.size();
  Bytes const nonce = m_rng.GetBytes(kNonceSize);
  file.insert(file.end(), nonce.begin(), nonce.end());
  file.resize(headerSize + kNonceSize + kMacSize + contents.size());
  crypto_aead_lock(file.data() + headerSize + kNonceSize + kMacSize, file.data() + headerSize + kNonceSize,
                   dataKey.data(), nonce.data(), file.data(), headerSize, contents.data(), contents.size());
  return WriteAtomically(m_path, file);
}

bool Store::Save(ByteSpan contents, std::set<ByteArray<32>> const & secretDigests)
{
  bool const erased = std::any_of(m_digests.begin(), m_digests.end(),
                                  [&](auto const & digest) { return secretDigests.count(digest) == 0; });
  m_lastRotated = false;
  if (erased || !m_dataKey || !m_wrapped)
  {
    Key const dataKey = m_rng.Get<32>();
    auto const wrapped = m_wrapper.Wrap(dataKey);
    if (!wrapped)
    {
      LOG(LWARNING, ("Live location: the platform key store could not wrap a new key"));
      return false;
    }
    if (!Write(contents, dataKey, *wrapped))
    {
      m_wrapper.DeleteAllExcept(m_wrapped ? m_wrapped->m_alias : std::string());
      return false;
    }
    // The new file is in place: old copies of the file become unreadable with the old wrapping key.
    m_wrapper.DeleteAllExcept(wrapped->m_alias);
    m_dataKey = dataKey;
    m_wrapped = *wrapped;
    m_lastRotated = true;
  }
  else if (!Write(contents, *m_dataKey, *m_wrapped))
  {
    return false;
  }
  m_digests = secretDigests;
  return true;
}

void Store::Erase()
{
  std::remove(m_path.c_str());
  std::remove((m_path + ".tmp").c_str());
  m_wrapper.DeleteAllExcept("");
  m_dataKey.reset();
  m_wrapped.reset();
  m_digests.clear();
}

std::optional<KeyWrapper::Wrapped> InsecureKeyWrapper::Wrap(Key const & dataKey)
{
  std::string alias = "nll-insecure-" + std::to_string(m_next++);
  m_aliases.insert(alias);
  return Wrapped{std::move(alias), Bytes(dataKey.begin(), dataKey.end())};
}

std::optional<Key> InsecureKeyWrapper::Unwrap(Wrapped const & wrapped)
{
  if (m_aliases.count(wrapped.m_alias) == 0 || wrapped.m_blob.size() != 32)
    return {};
  Key out;
  std::copy(wrapped.m_blob.begin(), wrapped.m_blob.end(), out.begin());
  return out;
}

void InsecureKeyWrapper::DeleteAllExcept(std::string const & keep)
{
  for (auto it = m_aliases.begin(); it != m_aliases.end();)
    it = *it == keep ? std::next(it) : m_aliases.erase(it);
}
}  // namespace live_location::store
