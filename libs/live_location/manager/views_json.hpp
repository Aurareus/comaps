#pragma once

#include "live_location/manager/types.hpp"
#include "live_location/protocol/json.hpp"

#include <vector>

// The manager's views as JSON objects with an "event" member: for the desktop peer's output and for the
// Android layer, which gets them as strings. Views only: no key ever leaves the core this way.
namespace live_location
{
json::Value PairingJson(PairingInfo const & pairing);
json::Value ContactsJson(std::vector<ContactInfo> const & contacts);
json::Value PositionsJson(std::vector<PositionInfo> const & positions);
json::Value SharingJson(SharingInfo const & sharing);
json::Value ConsentJson(ConsentRequest const & request);
json::Value LocationRequestJson(LocationRequest request);
/// `readable`: the store was read (Manager::IsStarted()); otherwise these are defaults, not the user's.
json::Value SettingsJson(Settings const & settings, bool readable = true);
char const * StageName(PairingInfo::Stage stage);
}  // namespace live_location
