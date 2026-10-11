#pragma once

#include "live_location/crypto/bytes.hpp"
#include "live_location/protocol/constants.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace live_location::json
{
/// A JSON value of a plaintext (spec §5). Senders build one with object members in insertion order,
/// and Dump() writes it exactly as Python's json.dumps(value, separators=(',', ':'),
/// ensure_ascii=False) does, which the test vectors were made with. Receivers get one from
/// ParseProfile(). Plaintexts carry keys and positions, so a Value wipes its strings and numbers when
/// it is destroyed.
class Value
{
public:
  enum class Type
  {
    Null,
    Bool,
    Int,
    Double,
    String,
    Array,
    Object
  };

  Value() = default;
  Value(Value const &) = default;
  Value(Value &&) = default;
  Value & operator=(Value const &) = default;
  Value & operator=(Value &&) = default;
  ~Value();

  static Value Bool(bool v);
  static Value Int(int64_t v);
  /// Throws std::invalid_argument for a value that is not finite.
  static Value Double(double v);
  static Value String(std::string v);
  static Value Array();
  static Value Object();

  /// Appends a member to an object.
  Value & Set(std::string key, Value value);
  /// Appends an element to an array.
  Value & Push(Value value);

  Type GetType() const { return m_type; }
  bool IsBool() const { return m_type == Type::Bool; }
  bool IsString() const { return m_type == Type::String; }
  bool IsArray() const { return m_type == Type::Array; }
  bool IsObject() const { return m_type == Type::Object; }
  /// A JSON integer (no fraction, no exponent) within [lo, hi]. Booleans are not numbers.
  bool IsInt(int64_t lo = 0, int64_t hi = kMaxJsonInt) const;
  /// Any JSON number; within [lo, hi]; at least lo.
  bool IsNumber() const;
  bool IsNumber(double lo, double hi) const;
  bool IsNumberAtLeast(double lo) const;

  bool AsBool() const { return m_bool; }
  int64_t AsInt() const { return m_int; }
  double AsNumber() const { return m_type == Type::Int ? static_cast<double>(m_int) : m_double; }
  std::string const & AsString() const { return m_string; }
  std::vector<Value> const & Elements() const { return m_elements; }

  /// The member of an object, or null if this is not an object or has no such member.
  Value const * Get(std::string_view key) const;

  /// Appends the JSON text to `out`.
  void DumpTo(std::string & out) const;
  std::string Dump() const;

private:
  friend class Parser;

  Type m_type = Type::Null;
  bool m_bool = false;
  int64_t m_int = 0;
  double m_double = 0;
  std::string m_string;
  std::vector<Value> m_elements;
  std::vector<std::pair<std::string, Value>> m_members;
};

/// The shortest decimal that reads back as `v`, written like Python's repr(float): "8.0", "52.5200066",
/// "1e-05", "1e+16". Throws std::invalid_argument for a value that is not finite.
std::string FormatDouble(double v);

/// Parses `text` under the I-JSON profile of spec §5, with the same verdicts as the Python reference:
/// valid UTF-8, no duplicate member names, no unpaired surrogates, finite numbers, integers within
/// +-(2^53 - 1), and nothing but whitespace around one value. Nothing on any violation.
std::optional<Value> ParseProfile(ByteSpan text);
}  // namespace live_location::json
