#include "live_location/protocol/messages.hpp"

#include "live_location/crypto/schnorr.hpp"
#include "live_location/encoding/base64.hpp"
#include "live_location/protocol/constants.hpp"

#include <stdexcept>

namespace live_location
{
namespace
{
bool IsPrintableAscii(std::string_view s)
{
  for (char const c : s)
    if (c < 0x21 || c > 0x7e)
      return false;
  return true;
}

// ws://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/[\x21-\x7e]*)?
bool IsLoopbackWsUrl(std::string_view url)
{
  std::string_view constexpr kPrefix = "ws://";
  if (!url.starts_with(kPrefix))
    return false;
  url.remove_prefix(kPrefix.size());
  for (std::string_view const host : {"localhost", "127.0.0.1", "[::1]"})
  {
    if (!url.starts_with(host))
      continue;
    std::string_view rest = url.substr(host.size());
    if (rest.starts_with(':'))
    {
      size_t digits = 0;
      while (1 + digits < rest.size() && rest[1 + digits] >= '0' && rest[1 + digits] <= '9')
        ++digits;
      if (digits < 1 || digits > 5)
        return false;
      rest.remove_prefix(1 + digits);
    }
    return rest.empty() || (rest.front() == '/' && IsPrintableAscii(rest.substr(1)));
  }
  return false;
}

std::optional<Relays> ParseRelays(json::Value const * value)
{
  if (value == nullptr || !value->IsArray())
    return {};
  Relays relays;
  for (auto const & element : value->Elements())
  {
    if (!element.IsString())
      return {};
    relays.push_back(element.AsString());
  }
  if (!IsValidRelayList(relays))
    return {};
  return relays;
}

json::Value RelaysJson(Relays const & relays)
{
  auto out = json::Value::Array();
  for (auto const & relay : relays)
    out.Push(json::Value::String(relay));
  return out;
}

bool HasType(json::Value const & message, std::string_view type)
{
  auto const * t = message.Get("t");
  return t != nullptr && t->IsString() && t->AsString() == type;
}

std::optional<Share> ParseShare(json::Value const & share)
{
  auto const * until = share.Get("until");
  auto const * pk = share.Get("pk");
  auto const * key = share.Get("key");
  if (!share.IsObject() || until == nullptr || !until->IsInt() || pk == nullptr || !pk->IsString() ||
      !IsValidPubkeyHex(pk->AsString()) || key == nullptr || !key->IsString())
  {
    return {};
  }
  auto decoded = Base64Decode(key->AsString());
  if (!decoded || decoded->size() != 32)
    return {};
  Share out;
  out.m_until = until->AsInt();
  out.m_pk = pk->AsString();
  std::copy(decoded->begin(), decoded->end(), out.m_key.begin());
  Wipe(decoded->data(), decoded->size());
  return out;
}

// Spec §12: an optional number that, when present, must satisfy `valid`.
template <typename Valid>
bool OptionalNumber(json::Value const & message, char const * name, Valid const & valid, std::optional<double> & out)
{
  auto const * v = message.Get(name);
  if (v == nullptr)
    return true;
  if (!valid(*v))
    return false;
  out = v->AsNumber();
  return true;
}

bool NonNegative(json::Value const & v)
{
  return v.IsNumberAtLeast(0);
}

bool AnyNumber(json::Value const & v)
{
  return v.IsNumber();
}
}  // namespace

bool IsValidRelayUrl(std::string_view url)
{
  if (url.size() > kMaxRelayUrl)
    return false;
  std::string_view constexpr kWss = "wss://";
  if (url.starts_with(kWss))
    return url.size() > kWss.size() && IsPrintableAscii(url.substr(kWss.size()));
  return IsLoopbackWsUrl(url);
}

bool IsValidRelayList(Relays const & relays)
{
  if (relays.empty() || relays.size() > kMaxRelays)
    return false;
  for (auto const & relay : relays)
    if (!IsValidRelayUrl(relay))
      return false;
  return true;
}

bool IsValidName(std::string_view name)
{
  return !name.empty() && name.size() <= kMaxName;
}

bool IsValidPubkeyHex(std::string_view pk)
{
  auto const bytes = FromHexArray<32>(pk);
  return bytes && crypto::IsValidXOnlyPublicKey(*bytes);
}

int64_t SeqOf(StreamMessage const & message)
{
  return std::visit([](auto const & m) { return m.m_seq; }, message);
}

json::Value ToJson(State const & state)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("state"))
      .Set("seq", json::Value::Int(state.m_seq))
      .Set("ts", json::Value::Int(state.m_ts))
      .Set("relays", RelaysJson(state.m_relays));
  if (state.m_share)
  {
    auto share = json::Value::Object();
    share.Set("until", json::Value::Int(state.m_share->m_until))
        .Set("pk", json::Value::String(state.m_share->m_pk))
        .Set("key", json::Value::String(Base64Encode(state.m_share->m_key)));
    out.Set("share", std::move(share));
  }
  if (state.m_color)
    out.Set("color", json::Value::String(*state.m_color));
  return out;
}

json::Value ToJson(Location const & location)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("loc"))
      .Set("seq", json::Value::Int(location.m_seq))
      .Set("ts", json::Value::Int(location.m_ts))
      .Set("lat", json::Value::Double(location.m_lat))
      .Set("lon", json::Value::Double(location.m_lon))
      .Set("acc", json::Value::Double(location.m_acc));
  if (location.m_spd)
    out.Set("spd", json::Value::Double(*location.m_spd));
  if (location.m_brg)
    out.Set("brg", json::Value::Double(*location.m_brg));
  if (location.m_alt)
    out.Set("alt", json::Value::Double(*location.m_alt));
  if (location.m_low)
    out.Set("low", json::Value::Bool(*location.m_low));
  if (location.m_nav)
  {
    auto nav = json::Value::Object();
    if (location.m_nav->m_eta)
      nav.Set("eta", json::Value::Int(*location.m_nav->m_eta));
    if (location.m_nav->m_dist)
      nav.Set("dist", json::Value::Double(*location.m_nav->m_dist));
    if (location.m_nav->m_dest)
      nav.Set("dest", json::Value::String(*location.m_nav->m_dest));
    out.Set("nav", std::move(nav));
  }
  return out;
}

json::Value ToJson(StreamEnd const & end)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("end"))
      .Set("seq", json::Value::Int(end.m_seq))
      .Set("ts", json::Value::Int(end.m_ts));
  return out;
}

json::Value ToJson(Watch const & watch)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("watch"))
      .Set("ts", json::Value::Int(watch.m_ts))
      .Set("until", json::Value::Int(watch.m_until));
  return out;
}

json::Value Pair1Json()
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("pair1"));
  return out;
}

json::Value ToJson(Pair2 const & pair2)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("pair2"))
      .Set("name", json::Value::String(pair2.m_name))
      .Set("relays", RelaysJson(pair2.m_relays));
  return out;
}

json::Value ToJson(Pair3 const & pair3)
{
  auto out = json::Value::Object();
  out.Set("t", json::Value::String("pair3")).Set("ok", json::Value::Bool(pair3.m_ok));
  if (pair3.m_ok)
  {
    out.Set("name", json::Value::String(pair3.m_name))
        .Set("relays", RelaysJson(pair3.m_relays))
        .Set("epoch", json::Value::Int(pair3.m_epoch));
  }
  return out;
}

SecretBytes EncodePlaintext(json::Value const & message, size_t size)
{
  std::string text;
  // Reserved up front, so that the buffer never moves and leaves an unwiped copy behind.
  text.reserve(2 * kSizeControl);
  message.DumpTo(text);
  if (text.size() > size)
  {
    Wipe(text.data(), text.size());
    throw std::length_error("NLL plaintext too long");
  }
  SecretBytes out(size);
  std::copy(text.begin(), text.end(), out.begin());
  std::fill(out.begin() + text.size(), out.end(), ' ');
  Wipe(text.data(), text.size());
  return out;
}

std::optional<json::Value> DecodePlaintext(ByteSpan data)
{
  if (data.size() > kSizeControl)
    return {};
  auto message = json::ParseProfile(data);
  if (!message || !message->IsObject())
    return {};
  auto const * t = message->Get("t");
  if (t == nullptr || !t->IsString())
    return {};
  return message;
}

std::string_view MessageType(json::Value const & message)
{
  auto const * t = message.Get("t");
  return t != nullptr && t->IsString() ? std::string_view(t->AsString()) : std::string_view();
}

std::optional<State> ParseState(json::Value const & message)
{
  auto const * seq = message.Get("seq");
  auto const * ts = message.Get("ts");
  if (!HasType(message, "state") || seq == nullptr || !seq->IsInt(1) || ts == nullptr || !ts->IsInt())
    return {};
  auto relays = ParseRelays(message.Get("relays"));
  if (!relays)
    return {};
  State out;
  out.m_seq = seq->AsInt();
  out.m_ts = ts->AsInt();
  out.m_relays = std::move(*relays);
  if (auto const * share = message.Get("share"))
  {
    out.m_share = ParseShare(*share);
    if (!out.m_share)
      return {};
  }
  // Cosmetic: a colour that isn't a short string is ignored, not the state with its grant (§8).
  if (auto const * color = message.Get("color");
      color != nullptr && color->IsString() && !color->AsString().empty() && color->AsString().size() <= kMaxColorBytes)
  {
    out.m_color = color->AsString();
  }
  return out;
}

std::optional<StreamMessage> ParseStreamMessage(json::Value const & message)
{
  auto const * seq = message.Get("seq");
  auto const * ts = message.Get("ts");
  if (seq == nullptr || !seq->IsInt(1) || ts == nullptr || !ts->IsInt())
    return {};

  if (HasType(message, "end"))
    return StreamEnd{seq->AsInt(), ts->AsInt()};
  if (!HasType(message, "loc"))
    return {};

  Location out;
  out.m_seq = seq->AsInt();
  out.m_ts = ts->AsInt();
  auto const * lat = message.Get("lat");
  auto const * lon = message.Get("lon");
  auto const * acc = message.Get("acc");
  if (lat == nullptr || !lat->IsNumber(-90, 90) || lon == nullptr || !lon->IsNumber(-180, 180) || acc == nullptr ||
      !acc->IsNumberAtLeast(0))
  {
    return {};
  }
  out.m_lat = lat->AsNumber();
  out.m_lon = lon->AsNumber();
  out.m_acc = acc->AsNumber();
  if (!OptionalNumber(message, "spd", NonNegative, out.m_spd) ||
      !OptionalNumber(message, "brg", NonNegative, out.m_brg) || !OptionalNumber(message, "alt", AnyNumber, out.m_alt))
  {
    return {};
  }
  if (out.m_brg && *out.m_brg >= 360)
    return {};
  if (auto const * low = message.Get("low"))
  {
    if (!low->IsBool())
      return {};
    out.m_low = low->AsBool();
  }
  if (auto const * nav = message.Get("nav"))
  {
    if (!nav->IsObject())
      return {};
    Nav n;
    if (auto const * eta = nav->Get("eta"))
    {
      if (!eta->IsInt())
        return {};
      n.m_eta = eta->AsInt();
    }
    if (!OptionalNumber(*nav, "dist", NonNegative, n.m_dist))
      return {};
    if (auto const * dest = nav->Get("dest"))
    {
      if (!dest->IsString() || dest->AsString().size() > kMaxDest)
        return {};
      n.m_dest = dest->AsString();
    }
    out.m_nav = std::move(n);
  }
  return out;
}

std::optional<Watch> ParseWatch(json::Value const & message)
{
  auto const * ts = message.Get("ts");
  auto const * until = message.Get("until");
  if (!HasType(message, "watch") || ts == nullptr || !ts->IsInt() || until == nullptr || !until->IsInt())
    return {};
  return Watch{ts->AsInt(), until->AsInt()};
}

std::optional<Pair2> ParsePair2(json::Value const & message)
{
  auto const * name = message.Get("name");
  if (!HasType(message, "pair2") || name == nullptr || !name->IsString() || !IsValidName(name->AsString()))
    return {};
  auto relays = ParseRelays(message.Get("relays"));
  if (!relays)
    return {};
  return Pair2{name->AsString(), std::move(*relays)};
}

std::optional<Pair3> ParsePair3(json::Value const & message)
{
  auto const * ok = message.Get("ok");
  if (!HasType(message, "pair3") || ok == nullptr || !ok->IsBool())
    return {};
  Pair3 out;
  out.m_ok = ok->AsBool();
  if (!out.m_ok)
    return out;
  auto const * name = message.Get("name");
  auto const * epoch = message.Get("epoch");
  if (name == nullptr || !name->IsString() || !IsValidName(name->AsString()) || epoch == nullptr || !epoch->IsInt())
    return {};
  auto relays = ParseRelays(message.Get("relays"));
  if (!relays)
    return {};
  out.m_name = name->AsString();
  out.m_relays = std::move(*relays);
  out.m_epoch = epoch->AsInt();
  return out;
}
}  // namespace live_location
