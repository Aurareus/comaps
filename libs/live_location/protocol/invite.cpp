#include "live_location/protocol/invite.hpp"

#include "live_location/crypto/hkdf.hpp"
#include "live_location/crypto/schnorr.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/common.hpp"
#include "live_location/protocol/constants.hpp"

#include <stdexcept>

namespace live_location
{
SecretBytes Invite::Encode() const
{
  if (!m_psk)
    throw std::logic_error("the invite's PSK has been erased");
  Bytes const pub = PublicFields();
  SecretBytes out(1 + m_psk->size() + pub.size());
  out[0] = kInviteVersion;
  std::copy(m_psk->begin(), m_psk->end(), out.begin() + 1);
  std::copy(pub.begin(), pub.end(), out.begin() + 1 + m_psk->size());
  return out;
}

Bytes Invite::PublicFields() const
{
  Bytes out(m_ipk.begin(), m_ipk.end());
  for (int shift = 24; shift >= 0; shift -= 8)
    out.push_back(static_cast<uint8_t>(m_expiresAt >> shift));
  out.push_back(static_cast<uint8_t>(m_relays.size()));
  for (auto const & relay : m_relays)
  {
    out.push_back(static_cast<uint8_t>(relay.size()));
    out.insert(out.end(), relay.begin(), relay.end());
  }
  return out;
}

std::string Invite::Link() const
{
  return std::string(kInviteLinkPrefix) + Base64UrlEncode(Encode());
}

std::optional<Invite> Invite::Decode(ByteSpan data)
{
  if (data.size() < 70 || data[0] != kInviteVersion)
    return {};
  Invite out;
  Key psk;
  std::copy_n(data.begin() + 1, 32, psk.begin());
  out.m_psk = psk;
  std::copy_n(data.begin() + 33, 32, out.m_ipk.begin());
  out.m_expiresAt = int64_t{data[65]} << 24 | int64_t{data[66]} << 16 | int64_t{data[67]} << 8 | data[68];
  size_t const n = data[69];
  size_t pos = 70;
  for (size_t i = 0; i < n; ++i)
  {
    if (pos >= data.size())
      return {};
    size_t const length = data[pos];
    if (pos + 1 + length > data.size())
      return {};
    out.m_relays.emplace_back(reinterpret_cast<char const *>(data.data() + pos + 1), length);
    pos += 1 + length;
  }
  if (pos != data.size() || !crypto::IsValidXOnlyPublicKey(out.m_ipk) || !IsValidRelayList(out.m_relays))
    return {};
  return out;
}

std::optional<Invite> Invite::FromLink(std::string_view link)
{
  if (!link.starts_with(kInviteLinkPrefix))
    return {};
  auto data = Base64UrlDecode(link.substr(kInviteLinkPrefix.size()));
  if (!data)
    return {};
  auto out = Decode(*data);
  Wipe(data->data(), data->size());
  return out;
}

Key Invite::MacKey() const
{
  if (!m_psk)
    throw std::logic_error("the invite's PSK has been erased");
  return crypto::HkdfExpandTo<32>(crypto::HkdfExtract(Label("pair"), *m_psk), Label("pair-mac"));
}

Bytes Invite::Prologue(ByteSpan jpk, ByteSpan c) const
{
  uint8_t const version = kInviteVersion;
  return Concat({Label("pair"), ByteSpan(&version, 1), PublicFields(), jpk, c});
}
}  // namespace live_location
