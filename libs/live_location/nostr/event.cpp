#include "live_location/nostr/event.hpp"

#include "live_location/crypto/schnorr.hpp"
#include "live_location/crypto/sha256.hpp"
#include "live_location/protocol/json.hpp"

namespace live_location::nostr
{
namespace
{
void AppendNip01String(std::string_view s, std::string & out)
{
  out += '"';
  for (char const c : s)
  {
    switch (c)
    {
    case '\n': out += "\\n"; break;
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    case '\b': out += "\\b"; break;
    case '\f': out += "\\f"; break;
    default: out += c;
    }
  }
  out += '"';
}

bool IsLowerHex(std::string_view s, size_t size)
{
  return s.size() == size && FromHex(s).has_value();
}

std::optional<std::string> String(json_t const * v)
{
  if (v == nullptr || !json_is_string(v))
    return {};
  return std::string(json_string_value(v), json_string_length(v));
}
}  // namespace

std::optional<std::string> Event::TagValue(std::string_view name) const
{
  for (auto const & tag : m_tags)
    if (tag.size() >= 2 && tag[0] == name)
      return tag[1];
  return {};
}

std::string Serialize(Event const & event)
{
  std::string out = "[0,";
  AppendNip01String(event.m_pubkey, out);
  out += ',' + std::to_string(event.m_createdAt) + ',' + std::to_string(event.m_kind) + ",[";
  for (size_t i = 0; i < event.m_tags.size(); ++i)
  {
    if (i != 0)
      out += ',';
    out += '[';
    for (size_t j = 0; j < event.m_tags[i].size(); ++j)
    {
      if (j != 0)
        out += ',';
      AppendNip01String(event.m_tags[i][j], out);
    }
    out += ']';
  }
  out += "],";
  AppendNip01String(event.m_content, out);
  out += ']';
  return out;
}

std::string ComputeId(Event const & event)
{
  return ToHex(crypto::Sha256(AsBytes(Serialize(event))));
}

void Sign(Event & event, Key const & secretKey, ByteArray<32> const & auxRandom)
{
  event.m_pubkey = ToHex(crypto::GetXOnlyPublicKey(secretKey));
  event.m_id = ComputeId(event);
  auto const id = FromHexArray<32>(event.m_id);
  event.m_sig = ToHex(crypto::SchnorrSign(secretKey, *id, auxRandom));
}

bool Verify(Event const & event)
{
  if (ComputeId(event) != event.m_id)
    return false;
  auto const pubkey = FromHexArray<32>(event.m_pubkey);
  auto const id = FromHexArray<32>(event.m_id);
  auto const sig = FromHexArray<64>(event.m_sig);
  return pubkey && id && sig && crypto::SchnorrVerify(*pubkey, *id, *sig);
}

std::string ToJson(Event const & event)
{
  auto tags = json::Value::Array();
  for (auto const & tag : event.m_tags)
  {
    auto t = json::Value::Array();
    for (auto const & v : tag)
      t.Push(json::Value::String(v));
    tags.Push(std::move(t));
  }
  auto out = json::Value::Object();
  out.Set("id", json::Value::String(event.m_id))
      .Set("pubkey", json::Value::String(event.m_pubkey))
      .Set("created_at", json::Value::Int(event.m_createdAt))
      .Set("kind", json::Value::Int(event.m_kind))
      .Set("tags", std::move(tags))
      .Set("content", json::Value::String(event.m_content))
      .Set("sig", json::Value::String(event.m_sig));
  return out.Dump();
}

std::optional<Event> FromJson(json_t const * object)
{
  if (object == nullptr || !json_is_object(object))
    return {};
  Event event;
  auto id = String(json_object_get(object, "id"));
  auto pubkey = String(json_object_get(object, "pubkey"));
  auto content = String(json_object_get(object, "content"));
  auto sig = String(json_object_get(object, "sig"));
  json_t const * createdAt = json_object_get(object, "created_at");
  json_t const * kind = json_object_get(object, "kind");
  json_t const * tags = json_object_get(object, "tags");
  if (!id || !IsLowerHex(*id, 64) || !pubkey || !IsLowerHex(*pubkey, 64) || !sig || !IsLowerHex(*sig, 128) ||
      !content || createdAt == nullptr || !json_is_integer(createdAt) || kind == nullptr || !json_is_integer(kind) ||
      tags == nullptr || !json_is_array(tags))
  {
    return {};
  }
  for (size_t i = 0; i < json_array_size(tags); ++i)
  {
    json_t const * tag = json_array_get(tags, i);
    if (!json_is_array(tag))
      return {};
    Tag t;
    for (size_t j = 0; j < json_array_size(tag); ++j)
    {
      auto v = String(json_array_get(tag, j));
      if (!v)
        return {};
      t.push_back(std::move(*v));
    }
    event.m_tags.push_back(std::move(t));
  }
  event.m_id = std::move(*id);
  event.m_pubkey = std::move(*pubkey);
  event.m_sig = std::move(*sig);
  event.m_content = std::move(*content);
  event.m_createdAt = json_integer_value(createdAt);
  event.m_kind = json_integer_value(kind);
  return event;
}
}  // namespace live_location::nostr
