#include "live_location/protocol/persist.hpp"

#include "live_location/crypto/schnorr.hpp"

namespace live_location::persist
{
void WriteRelays(binary::Writer & writer, Relays const & relays)
{
  writer.U32(static_cast<uint32_t>(relays.size()));
  for (auto const & url : relays)
    writer.String(url);
}

Relays ReadRelays(binary::Reader & reader)
{
  Relays out;
  uint32_t const n = reader.Count(4);
  for (uint32_t i = 0; i < n; ++i)
    out.push_back(reader.String());
  if (!IsValidRelayList(out))
    throw binary::FormatError("relay list");
  return out;
}

void WriteDirection(binary::Writer & writer, Direction const & direction)
{
  writer.I64(direction.Epoch());
  writer.Secret(direction.ChainKey());
}

Direction ReadDirection(binary::Reader & reader)
{
  int64_t const epoch = reader.I64();
  Key const chainKey = reader.Secret();
  return Direction(epoch, chainKey);
}

void WriteContact(binary::Writer & writer, Contact const & contact)
{
  writer.String(contact.m_name);
  WriteRelays(writer, contact.m_relays);
  WriteDirection(writer, contact.m_outgoing);
  WriteDirection(writer, contact.m_incoming);
  writer.String(contact.m_sas);
  writer.I64(contact.m_pairingEpoch);
  writer.Bool(contact.m_joiner);
  writer.I64(contact.m_lastSeqIn);
  writer.I64(contact.m_seqOut);
  writer.I64(contact.m_lastCreatedOut);
  writer.Bool(contact.m_verified);
  writer.Bool(contact.m_flagged);
  writer.Bool(contact.m_confirmed);
}

ContactPtr ReadContact(binary::Reader & reader)
{
  std::string name = reader.String();
  Relays relays = ReadRelays(reader);
  Direction outgoing = ReadDirection(reader);
  Direction incoming = ReadDirection(reader);
  std::string sas = reader.String();
  auto contact = std::make_shared<Contact>(std::move(name), std::move(relays), std::move(outgoing), std::move(incoming),
                                           std::move(sas));
  contact->m_pairingEpoch = reader.I64();
  contact->m_joiner = reader.Bool();
  contact->m_lastSeqIn = reader.I64();
  contact->m_seqOut = reader.I64();
  contact->m_lastCreatedOut = reader.I64();
  contact->m_verified = reader.Bool();
  contact->m_flagged = reader.Bool();
  contact->m_confirmed = reader.Bool();
  return contact;
}

void WriteInvite(binary::Writer & writer, Invite const & invite)
{
  writer.OptionalSecret(invite.m_psk);
  writer.Raw(invite.m_ipk);
  writer.I64(invite.m_expiresAt);
  WriteRelays(writer, invite.m_relays);
}

Invite ReadInvite(binary::Reader & reader)
{
  Invite invite;
  invite.m_psk = reader.OptionalSecret();
  invite.m_ipk = reader.Array<32>();
  invite.m_expiresAt = reader.I64();
  invite.m_relays = ReadRelays(reader);
  if (!crypto::IsValidXOnlyPublicKey(invite.m_ipk))
    throw binary::FormatError("invite key");
  return invite;
}

void WriteEvent(binary::Writer & writer, nostr::Event const & event)
{
  writer.String(event.m_id);
  writer.String(event.m_pubkey);
  writer.I64(event.m_createdAt);
  writer.I64(event.m_kind);
  writer.U32(static_cast<uint32_t>(event.m_tags.size()));
  for (auto const & tag : event.m_tags)
  {
    writer.U32(static_cast<uint32_t>(tag.size()));
    for (auto const & value : tag)
      writer.String(value);
  }
  writer.String(event.m_content);
  writer.String(event.m_sig);
}

nostr::Event ReadEvent(binary::Reader & reader)
{
  nostr::Event event;
  event.m_id = reader.String();
  event.m_pubkey = reader.String();
  event.m_createdAt = reader.I64();
  event.m_kind = reader.I64();
  uint32_t const tags = reader.Count(4);
  for (uint32_t i = 0; i < tags; ++i)
  {
    nostr::Tag tag;
    uint32_t const values = reader.Count(4);
    for (uint32_t j = 0; j < values; ++j)
      tag.push_back(reader.String());
    event.m_tags.push_back(std::move(tag));
  }
  event.m_content = reader.String();
  event.m_sig = reader.String();
  return event;
}

void WriteOptionalEvent(binary::Writer & writer, std::optional<nostr::Event> const & event)
{
  writer.Bool(event.has_value());
  if (event)
    WriteEvent(writer, *event);
}

std::optional<nostr::Event> ReadOptionalEvent(binary::Reader & reader)
{
  if (!reader.Bool())
    return {};
  return ReadEvent(reader);
}
}  // namespace live_location::persist
