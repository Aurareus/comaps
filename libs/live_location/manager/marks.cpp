#include "live_location/manager/marks.hpp"

#include "live_location/crypto/sha256.hpp"

#include <array>

namespace live_location
{
namespace
{
// Distinct on a map in daylight and at night; none of them grey.
std::array<uint32_t, 8> constexpr kPalette = {0xE53935FF, 0x1E88E5FF, 0x43A047FF, 0xFB8C00FF,
                                              0x8E24AAFF, 0x00ACC1FF, 0xD81B60FF, 0x6D4C41FF};
}  // namespace

// The values of kml::ColorFromPredefinedColor(), which this library does not depend on.
std::array<DotColor, 14> const kDotColors = {{
    {"red", 0xE51B23FF},
    {"pink", 0xFF4182FF},
    {"purple", 0x9B24B2FF},
    {"deeppurple", 0x6639BFFF},
    {"blue", 0x0066CCFF},
    {"lightblue", 0x249CF2FF},
    {"cyan", 0x14BECDFF},
    {"teal", 0x00A58CFF},
    {"green", 0x3C8C3CFF},
    {"lime", 0x93BF39FF},
    {"yellow", 0xFFC800FF},
    {"orange", 0xFF9600FF},
    {"deeporange", 0xF06432FF},
    {"brown", 0x804633FF},
}};

std::optional<uint32_t> DotColorRgba(std::string_view name)
{
  for (auto const & color : kDotColors)
    if (color.m_name == name)
      return color.m_rgba;
  return {};
}

uint32_t ColorOf(std::string const & contactId)
{
  auto const digest = crypto::Sha256(AsBytes(contactId));
  return kPalette[digest[0] % kPalette.size()];
}

std::vector<MarkSpec> MarksFor(std::vector<PositionInfo> const & positions)
{
  std::vector<MarkSpec> out;
  for (auto const & position : positions)
  {
    MarkSpec mark;
    mark.m_contactId = position.m_contactId;
    mark.m_lat = position.m_location.m_lat;
    mark.m_lon = position.m_location.m_lon;
    mark.m_label = position.m_name;
    mark.m_stale = position.m_stale;
    mark.m_rgba =
        position.m_stale ? kStaleColor : DotColorRgba(position.m_color).value_or(ColorOf(position.m_contactId));
    out.push_back(std::move(mark));
  }
  return out;
}

void MarksSync::Apply(std::vector<MarkSpec> const & marks, MarkSink & sink)
{
  std::map<std::string, Shown> next;
  for (auto const & mark : marks)
  {
    auto const it = m_shown.find(mark.m_contactId);
    if (it == m_shown.end())
    {
      next[mark.m_contactId] = {sink.Create(mark), mark};
      continue;
    }
    if (!(it->second.m_mark == mark))
      sink.Update(it->second.m_handle, mark);
    next[mark.m_contactId] = {it->second.m_handle, mark};
    m_shown.erase(it);
  }
  for (auto const & gone : m_shown)
    sink.Remove(gone.second.m_handle);
  m_shown = std::move(next);
}
}  // namespace live_location
