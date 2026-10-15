#pragma once

#include "live_location/manager/types.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Contacts' positions as dots on the map (design doc §11.4): the decisions, without the map. libs/map
// draws them; tests use a stub.
namespace live_location
{
struct MarkSpec
{
  std::string m_contactId;
  double m_lat = 0;
  double m_lon = 0;
  std::string m_label;
  uint32_t m_rgba = 0;  // the contact's colour, or grey once the position is old or its stream ended
  bool m_stale = false;

  bool operator==(MarkSpec const &) const = default;
};

uint32_t constexpr kStaleColor = 0x9E9E9EFF;

/// A colour per contact, the same for its id on every run.
uint32_t ColorOf(std::string const & contactId);

/// One mark per position.
std::vector<MarkSpec> MarksFor(std::vector<PositionInfo> const & positions);

/// The map's side.
class MarkSink
{
public:
  using Handle = uint64_t;

  virtual ~MarkSink() = default;
  virtual Handle Create(MarkSpec const & mark) = 0;
  virtual void Update(Handle handle, MarkSpec const & mark) = 0;
  virtual void Remove(Handle handle) = 0;
};

/// Shows successive sets of marks with the fewest changes: one mark per contact, updated in place.
class MarksSync
{
public:
  void Apply(std::vector<MarkSpec> const & marks, MarkSink & sink);
  void Clear(MarkSink & sink) { Apply({}, sink); }

private:
  struct Shown
  {
    MarkSink::Handle m_handle = 0;
    MarkSpec m_mark;
  };
  std::map<std::string, Shown> m_shown;  // by contact id
};
}  // namespace live_location
