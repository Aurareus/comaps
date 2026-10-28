#include "live_location/protocol/json.hpp"

#include <algorithm>
#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <fast_double_parser.h>

namespace live_location::json
{
// Not std::isfinite: unless the optimiser inlines it, it is an inline function shared between translation
// units, and the linker may keep the copy of one built with the project's -ffast-math, which folds it to
// true (debug builds then accept 1e400). Not inline, so this definition built here is the only one.
bool IsFinite(double d)
{
  uint64_t bits;
  std::memcpy(&bits, &d, sizeof(bits));
  return ((bits >> 52) & 0x7ff) != 0x7ff;
}

namespace
{
// Plaintexts are at most 512 bytes: a valid document nests at most 256 levels, but the parser recurses into each
// "[" before it can see the input end, so 512 of them reach a depth of 512. That is the bound.
size_t constexpr kMaxDepth = 512;

char LocaleDecimalPoint()
{
  char const * point = std::localeconv()->decimal_point;
  return point != nullptr && *point != '\0' ? *point : '.';
}

// `token` matches the JSON number grammar. Locale-independent: the C library reads and writes the
// decimal point of the current C locale, which need not be '.'.
bool ParseDouble(std::string_view token, double & out)
{
  std::string s(token);
  char const * end = fast_double_parser::parse_number(s.c_str(), &out);
  if (end == s.c_str() + s.size())
    return true;
  // fast_double_parser gives up on some valid inputs, e.g. very long mantissas.
  std::replace(s.begin(), s.end(), '.', LocaleDecimalPoint());
  char * stop = nullptr;
  errno = 0;
  out = std::strtod(s.c_str(), &stop);
  return stop == s.c_str() + s.size();
}

// Python's json.dumps with ensure_ascii=False: the two-character escapes, \u00XX (lowercase) for the
// other control characters, and everything else verbatim.
void DumpString(std::string_view s, std::string & out)
{
  out += '"';
  for (char const c : s)
  {
    switch (c)
    {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    case '\b': out += "\\b"; break;
    case '\f': out += "\\f"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20)
      {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
        out += buf;
      }
      else
      {
        out += c;
      }
    }
  }
  out += '"';
}

void AppendUtf8(uint32_t cp, std::string & out)
{
  if (cp < 0x80)
  {
    out += static_cast<char>(cp);
  }
  else if (cp < 0x800)
  {
    out += static_cast<char>(0xC0 | cp >> 6);
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
  else if (cp < 0x10000)
  {
    out += static_cast<char>(0xE0 | cp >> 12);
    out += static_cast<char>(0x80 | (cp >> 6 & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
  else
  {
    out += static_cast<char>(0xF0 | cp >> 18);
    out += static_cast<char>(0x80 | (cp >> 12 & 0x3F));
    out += static_cast<char>(0x80 | (cp >> 6 & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}
}  // namespace

// A strict recursive-descent parser for RFC 8259 JSON under the profile. It agrees with the Python
// reference (json.loads with its profile hooks) on every input, which the receiving-rule tests check.
class Parser
{
public:
  explicit Parser(ByteSpan text) : m_p(text.data()), m_end(text.data() + text.size()) {}

  std::optional<Value> ParseDocument()
  {
    SkipWhitespace();
    Value value;
    if (!ParseValue(value, 0))
      return {};
    SkipWhitespace();
    if (m_p != m_end)
      return {};
    return value;
  }

private:
  bool AtEnd() const { return m_p == m_end; }

  void SkipWhitespace()
  {
    while (!AtEnd() && (*m_p == ' ' || *m_p == '\t' || *m_p == '\n' || *m_p == '\r'))
      ++m_p;
  }

  bool Consume(char c)
  {
    if (AtEnd() || *m_p != c)
      return false;
    ++m_p;
    return true;
  }

  bool ConsumeLiteral(std::string_view literal)
  {
    if (static_cast<size_t>(m_end - m_p) < literal.size() ||
        std::string_view(reinterpret_cast<char const *>(m_p), literal.size()) != literal)
    {
      return false;
    }
    m_p += literal.size();
    return true;
  }

  bool ParseValue(Value & out, size_t depth)
  {
    if (depth > kMaxDepth || AtEnd())
      return false;
    switch (*m_p)
    {
    case '{': return ParseObject(out, depth);
    case '[': return ParseArray(out, depth);
    case '"': out.m_type = Value::Type::String; return ParseString(out.m_string);
    case 't': out = Value::Bool(true); return ConsumeLiteral("true");
    case 'f': out = Value::Bool(false); return ConsumeLiteral("false");
    case 'n': out = Value(); return ConsumeLiteral("null");
    default: return ParseNumber(out);
    }
  }

  bool ParseObject(Value & out, size_t depth)
  {
    out = Value::Object();
    ++m_p;  // '{'
    SkipWhitespace();
    if (Consume('}'))
      return true;
    while (true)
    {
      SkipWhitespace();
      std::string key;
      if (AtEnd() || *m_p != '"' || !ParseString(key))
        return false;
      for (auto const & member : out.m_members)
        if (member.first == key)
          return false;  // a duplicate member name
      SkipWhitespace();
      if (!Consume(':'))
        return false;
      SkipWhitespace();
      Value value;
      if (!ParseValue(value, depth + 1))
        return false;
      out.m_members.emplace_back(std::move(key), std::move(value));
      SkipWhitespace();
      if (Consume('}'))
        return true;
      if (!Consume(','))
        return false;
    }
  }

  bool ParseArray(Value & out, size_t depth)
  {
    out = Value::Array();
    ++m_p;  // '['
    SkipWhitespace();
    if (Consume(']'))
      return true;
    while (true)
    {
      SkipWhitespace();
      Value value;
      if (!ParseValue(value, depth + 1))
        return false;
      out.m_elements.push_back(std::move(value));
      SkipWhitespace();
      if (Consume(']'))
        return true;
      if (!Consume(','))
        return false;
    }
  }

  bool ParseHex4(uint32_t & out)
  {
    if (m_end - m_p < 4)
      return false;
    out = 0;
    for (int i = 0; i < 4; ++i)
    {
      uint8_t const c = *m_p++;
      uint32_t digit;
      if (c >= '0' && c <= '9')
        digit = c - '0';
      else if (c >= 'a' && c <= 'f')
        digit = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        digit = c - 'A' + 10;
      else
        return false;
      out = out << 4 | digit;
    }
    return true;
  }

  // One well-formed UTF-8 sequence (no overlong forms, no surrogates, at most U+10FFFF), copied as is.
  bool CopyUtf8Sequence(std::string & out)
  {
    uint8_t const b0 = *m_p;
    size_t length;
    uint32_t cp;
    if (b0 >= 0xC2 && b0 <= 0xDF)
    {
      length = 2;
      cp = b0 & 0x1F;
    }
    else if (b0 >= 0xE0 && b0 <= 0xEF)
    {
      length = 3;
      cp = b0 & 0x0F;
    }
    else if (b0 >= 0xF0 && b0 <= 0xF4)
    {
      length = 4;
      cp = b0 & 0x07;
    }
    else
    {
      return false;
    }
    if (static_cast<size_t>(m_end - m_p) < length)
      return false;
    for (size_t i = 1; i < length; ++i)
    {
      if ((m_p[i] & 0xC0) != 0x80)
        return false;
      cp = cp << 6 | (m_p[i] & 0x3F);
    }
    bool const overlong = (length == 3 && cp < 0x800) || (length == 4 && cp < 0x10000);
    if (overlong || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
      return false;
    out.append(reinterpret_cast<char const *>(m_p), length);
    m_p += length;
    return true;
  }

  bool ParseString(std::string & out)
  {
    out.clear();
    // Reserved up front, so that the buffer never moves and leaves an unwiped copy behind.
    out.reserve(static_cast<size_t>(m_end - m_p));
    ++m_p;  // '"'
    while (true)
    {
      if (AtEnd())
        return false;
      uint8_t const c = *m_p;
      if (c == '"')
      {
        ++m_p;
        return true;
      }
      if (c < 0x20)
        return false;  // raw control characters are not allowed in strings
      if (c >= 0x80)
      {
        if (!CopyUtf8Sequence(out))
          return false;
        continue;
      }
      ++m_p;
      if (c != '\\')
      {
        out += static_cast<char>(c);
        continue;
      }
      if (AtEnd())
        return false;
      switch (*m_p++)
      {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'u':
      {
        uint32_t cp;
        if (!ParseHex4(cp))
          return false;
        if (cp >= 0xDC00 && cp <= 0xDFFF)
          return false;  // an unpaired low surrogate
        if (cp >= 0xD800 && cp <= 0xDBFF)
        {
          uint32_t low;
          if (!ConsumeLiteral("\\u") || !ParseHex4(low) || low < 0xDC00 || low > 0xDFFF)
            return false;  // an unpaired high surrogate
          cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
        }
        AppendUtf8(cp, out);
        break;
      }
      default: return false;
      }
    }
  }

  bool ParseNumber(Value & out)
  {
    uint8_t const * start = m_p;
    Consume('-');
    if (AtEnd())
      return false;
    if (*m_p == '0')
      ++m_p;
    else if (*m_p >= '1' && *m_p <= '9')
      while (!AtEnd() && *m_p >= '0' && *m_p <= '9')
        ++m_p;
    else
      return false;
    bool isInteger = true;
    if (Consume('.'))
    {
      isInteger = false;
      if (AtEnd() || *m_p < '0' || *m_p > '9')
        return false;
      while (!AtEnd() && *m_p >= '0' && *m_p <= '9')
        ++m_p;
    }
    if (!AtEnd() && (*m_p == 'e' || *m_p == 'E'))
    {
      isInteger = false;
      ++m_p;
      if (!Consume('+'))
        Consume('-');
      if (AtEnd() || *m_p < '0' || *m_p > '9')
        return false;
      while (!AtEnd() && *m_p >= '0' && *m_p <= '9')
        ++m_p;
    }
    std::string_view const token(reinterpret_cast<char const *>(start), m_p - start);

    if (isInteger)
    {
      bool const negative = token.front() == '-';
      uint64_t magnitude = 0;
      for (char const c : token.substr(negative ? 1 : 0))
      {
        magnitude = magnitude * 10 + static_cast<uint64_t>(c - '0');
        if (magnitude > static_cast<uint64_t>(kMaxJsonInt))
          return false;  // beyond +-(2^53 - 1); checked per digit, so it cannot overflow
      }
      out = Value::Int(negative ? -static_cast<int64_t>(magnitude) : static_cast<int64_t>(magnitude));
      return true;
    }
    double d;
    if (!ParseDouble(token, d) || !IsFinite(d))
      return false;
    out.m_type = Value::Type::Double;
    out.m_double = d;
    return true;
  }

  uint8_t const * m_p;
  uint8_t const * m_end;
};

Value::~Value()
{
  Wipe(m_string.data(), m_string.size());
  Wipe(&m_int, sizeof(m_int));
  Wipe(&m_double, sizeof(m_double));
}

Value Value::Bool(bool v)
{
  Value out;
  out.m_type = Type::Bool;
  out.m_bool = v;
  return out;
}

Value Value::Int(int64_t v)
{
  Value out;
  out.m_type = Type::Int;
  out.m_int = v;
  return out;
}

Value Value::Double(double v)
{
  if (!IsFinite(v))
    throw std::invalid_argument("JSON numbers are finite");
  Value out;
  out.m_type = Type::Double;
  out.m_double = v;
  return out;
}

Value Value::String(std::string v)
{
  Value out;
  out.m_type = Type::String;
  out.m_string = std::move(v);
  return out;
}

Value Value::Array()
{
  Value out;
  out.m_type = Type::Array;
  return out;
}

Value Value::Object()
{
  Value out;
  out.m_type = Type::Object;
  return out;
}

Value & Value::Set(std::string key, Value value)
{
  if (m_type != Type::Object)
    throw std::logic_error("Set() on a JSON value that is not an object");
  m_members.emplace_back(std::move(key), std::move(value));
  return *this;
}

Value & Value::Push(Value value)
{
  if (m_type != Type::Array)
    throw std::logic_error("Push() on a JSON value that is not an array");
  m_elements.push_back(std::move(value));
  return *this;
}

bool Value::IsInt(int64_t lo, int64_t hi) const
{
  return m_type == Type::Int && m_int >= lo && m_int <= hi;
}

bool Value::IsNumber() const
{
  return (m_type == Type::Int || m_type == Type::Double) && IsFinite(AsNumber());
}

bool Value::IsNumber(double lo, double hi) const
{
  return IsNumber() && AsNumber() >= lo && AsNumber() <= hi;
}

bool Value::IsNumberAtLeast(double lo) const
{
  return IsNumber() && AsNumber() >= lo;
}

Value const * Value::Get(std::string_view key) const
{
  if (m_type != Type::Object)
    return nullptr;
  for (auto const & member : m_members)
    if (member.first == key)
      return &member.second;
  return nullptr;
}

std::string Value::Dump() const
{
  std::string out;
  DumpTo(out);
  return out;
}

void Value::DumpTo(std::string & out) const
{
  switch (m_type)
  {
  case Type::Null: out += "null"; break;
  case Type::Bool: out += m_bool ? "true" : "false"; break;
  case Type::Int: out += std::to_string(m_int); break;
  case Type::Double: out += FormatDouble(m_double); break;
  case Type::String: DumpString(m_string, out); break;
  case Type::Array:
    out += '[';
    for (size_t i = 0; i < m_elements.size(); ++i)
    {
      if (i != 0)
        out += ',';
      m_elements[i].DumpTo(out);
    }
    out += ']';
    break;
  case Type::Object:
    out += '{';
    for (size_t i = 0; i < m_members.size(); ++i)
    {
      if (i != 0)
        out += ',';
      DumpString(m_members[i].first, out);
      out += ':';
      m_members[i].second.DumpTo(out);
    }
    out += '}';
    break;
  }
}

// The fewest significant digits that read back as `v` (the C library rounds correctly both ways), then
// Python's layout: positional notation for decimal exponents in [-4, 16), otherwise "1e-05" style.
std::string FormatDouble(double v)
{
  if (!IsFinite(v))
    throw std::invalid_argument("JSON numbers are finite");

  char const point = LocaleDecimalPoint();
  std::string text;
  for (int precision = 1; precision <= 17; ++precision)
  {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.*e", precision - 1, v);
    text = buf;
    std::replace(text.begin(), text.end(), point, '.');
    double back;
    if (ParseDouble(text, back) && back == v)
      break;
  }
  // text is "[-]d[.ddd]e[+-]xx".
  bool const negative = text.front() == '-';
  size_t const ePos = text.find('e');
  std::string digits;
  for (size_t i = negative ? 1 : 0; i < ePos; ++i)
    if (text[i] != '.')
      digits += text[i];
  int const exponent = std::atoi(text.c_str() + ePos + 1);
  // Only 0 can end in a zero here ("0e+00"); keep one digit.
  while (digits.size() > 1 && digits.back() == '0')
    digits.pop_back();

  std::string out = negative ? "-" : "";
  int const n = static_cast<int>(digits.size());
  if (exponent >= -4 && exponent < 16)
  {
    int const pointPos = exponent + 1;  // digits before the decimal point
    if (pointPos <= 0)
      out += "0." + std::string(-pointPos, '0') + digits;
    else if (pointPos < n)
      out += digits.substr(0, pointPos) + "." + digits.substr(pointPos);
    else
      out += digits + std::string(pointPos - n, '0') + ".0";
  }
  else
  {
    out += digits.substr(0, 1);
    if (n > 1)
      out += "." + digits.substr(1);
    std::string const e = std::to_string(std::abs(exponent));
    out += exponent < 0 ? "e-" : "e+";
    if (e.size() < 2)
      out += '0';
    out += e;
  }
  return out;
}

std::optional<Value> ParseProfile(ByteSpan text)
{
  return Parser(text).ParseDocument();
}
}  // namespace live_location::json
