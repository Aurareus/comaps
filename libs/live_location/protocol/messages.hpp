#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/protocol/json.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// The plaintext messages of NLL v1 (spec §5, §6.3, §8–§10) and the field checks of §12.
namespace live_location
{
using Relays = std::vector<std::string>;

/// wss:// with printable ASCII but quotes and backslashes, or ws:// to a loopback host; at most 64 bytes
/// (spec §5). Patterns rather than a URL parser, so that implementations agree byte for byte.
bool IsValidRelayUrl(std::string_view url);
/// 1 to 4 valid URLs.
bool IsValidRelayList(Relays const & relays);
/// 1 to 64 bytes without control characters.
bool IsValidName(std::string_view name);
/// 64 lowercase hex characters that encode a valid x-only key.
bool IsValidPubkeyHex(std::string_view pk);

/// A grant of the sharer's stream to one recipient (spec §8).
struct Share
{
  int64_t m_until = 0;  // when this recipient's access ends, 0 meaning until stopped
  std::string m_pk;     // the stream's public key, hex
  Key m_key;            // the stream's NIP-44 conversation key
};

/// The sender's current state towards one contact (spec §8).
struct State
{
  int64_t m_seq = 0;
  int64_t m_ts = 0;
  Relays m_relays;
  std::optional<Share> m_share;
  std::optional<std::string> m_color;  // the sender's dot colour: a name; one the receiver doesn't know is ignored
};

size_t constexpr kMaxColorBytes = 32;

struct Nav
{
  std::optional<int64_t> m_eta;
  std::optional<double> m_dist;
  std::optional<std::string> m_dest;
};

/// A position of a stream (spec §9). `m_ts` is the fix time in milliseconds.
struct Location
{
  int64_t m_seq = 0;
  int64_t m_ts = 0;
  double m_lat = 0;
  double m_lon = 0;
  double m_acc = 0;
  std::optional<double> m_spd;
  std::optional<double> m_brg;
  std::optional<double> m_alt;
  std::optional<bool> m_low;
  std::optional<Nav> m_nav;
};

struct StreamEnd
{
  int64_t m_seq = 0;
  int64_t m_ts = 0;
};

using StreamMessage = std::variant<Location, StreamEnd>;
int64_t SeqOf(StreamMessage const & message);

struct Watch
{
  int64_t m_ts = 0;
  int64_t m_until = 0;
};

struct Pair2
{
  std::string m_name;
  Relays m_relays;
};

struct Pair3
{
  bool m_ok = false;
  std::string m_name;   // when ok
  Relays m_relays;      // when ok
  int64_t m_epoch = 0;  // when ok: e_p
};

json::Value ToJson(State const & state);
json::Value ToJson(Location const & location);
json::Value ToJson(StreamEnd const & end);
json::Value ToJson(Watch const & watch);
json::Value Pair1Json();
json::Value ToJson(Pair2 const & pair2);
json::Value ToJson(Pair3 const & pair3);

/// The JSON text padded with spaces to exactly `size` bytes. Throws std::length_error if it does not fit.
SecretBytes EncodePlaintext(json::Value const & message, size_t size);

/// Spec §12 item 5: at most 512 bytes of profile JSON forming an object with a string "t".
std::optional<json::Value> DecodePlaintext(ByteSpan data);
/// The "t" of a decoded plaintext.
std::string_view MessageType(json::Value const & message);

// The field checks of spec §12. Unknown members are ignored; an invalid optional member makes the
// whole message invalid.
std::optional<State> ParseState(json::Value const & message);
std::optional<StreamMessage> ParseStreamMessage(json::Value const & message);  // "loc" or "end"
std::optional<Watch> ParseWatch(json::Value const & message);
std::optional<Pair2> ParsePair2(json::Value const & message);
/// Checks "ok" and, when it is true, the name, relays and that the epoch is an integer >= 0; the
/// caller checks the epoch's range against its clock (spec §6.3).
std::optional<Pair3> ParsePair3(json::Value const & message);
}  // namespace live_location
