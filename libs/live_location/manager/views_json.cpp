#include "live_location/manager/views_json.hpp"

#include "live_location/manager/manager.hpp"
#include "live_location/manager/marks.hpp"
#include "live_location/protocol/constants.hpp"

namespace live_location
{
namespace
{
json::Value Optional(std::optional<int64_t> const & value)
{
  return value ? json::Value::Int(*value) : json::Value();
}
}  // namespace

char const * StageName(PairingInfo::Stage stage)
{
  switch (stage)
  {
  case PairingInfo::Stage::NeedsConsent: return "NeedsConsent";
  case PairingInfo::Stage::Waiting: return "Waiting";
  case PairingInfo::Stage::CompareCode: return "CompareCode";
  case PairingInfo::Stage::Connected: return "Connected";
  case PairingInfo::Stage::Declined: return "Declined";
  case PairingInfo::Stage::Cancelled: return "Cancelled";
  case PairingInfo::Stage::Conflict: return "Conflict";
  case PairingInfo::Stage::Expired: return "Expired";
  }
  return "?";
}

json::Value PairingJson(PairingInfo const & p)
{
  auto consent = json::Value::Array();
  for (auto const & url : p.m_needsConsent)
    consent.Push(json::Value::String(url));
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("pairing"))
      .Set("id", json::Value::String(p.m_id))
      .Set("inviter", json::Value::Bool(p.m_inviter))
      .Set("by_link", json::Value::Bool(p.m_byLink))
      .Set("stage", json::Value::String(StageName(p.m_stage)))
      .Set("link", json::Value::String(p.m_link))
      .Set("expires", json::Value::Int(p.m_expiresAt))
      .Set("sas", json::Value::String(p.m_sas))
      .Set("peer", json::Value::String(p.m_peerName))
      .Set("contact", json::Value::String(p.m_contactId))
      .Set("consent", std::move(consent));
  return out;
}

json::Value ContactsJson(std::vector<ContactInfo> const & contacts)
{
  auto list = json::Value::Array();
  for (auto const & c : contacts)
  {
    auto item = json::Value::Object();
    item.Set("id", json::Value::String(c.m_id))
        .Set("name", json::Value::String(c.m_name))
        .Set("sas", json::Value::String(c.m_sas))
        .Set("verified", json::Value::Bool(c.m_verified))
        .Set("flagged", json::Value::Bool(c.m_flagged))
        .Set("waiting", json::Value::Bool(c.m_waiting))
        .Set("offer_removal", json::Value::Bool(c.m_offerRemoval))
        .Set("hidden", json::Value::Bool(c.m_hidden))
        .Set("not_moved", json::Value::Bool(c.m_notMoved))
        .Set("move_overdue", json::Value::Bool(c.m_moveOverdue))
        .Set("shares_with_me", Optional(c.m_sharesWithMeUntil))
        .Set("i_share", Optional(c.m_iShareUntil))
        .Set("live_updates_off", json::Value::Bool(c.m_liveUpdatesOff))
        .Set("live_relay", json::Value::String(c.m_liveRelay))
        .Set("blocked_relay", json::Value::String(c.m_blockedRelay))
        .Set("color", json::Value::String(c.m_color));
    list.Push(std::move(item));
  }
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("contacts")).Set("contacts", std::move(list));
  return out;
}

json::Value PositionsJson(std::vector<PositionInfo> const & positions)
{
  auto list = json::Value::Array();
  for (auto const & p : positions)
  {
    auto item = json::Value::Object();
    item.Set("id", json::Value::String(p.m_contactId))
        .Set("name", json::Value::String(p.m_name))
        .Set("lat", json::Value::Double(p.m_location.m_lat))
        .Set("lon", json::Value::Double(p.m_location.m_lon))
        .Set("acc", json::Value::Double(p.m_location.m_acc))
        .Set("ts", json::Value::Int(p.m_location.m_ts))
        .Set("stale", json::Value::Bool(p.m_stale))
        .Set("low", json::Value::Bool(p.m_location.m_low.value_or(false)))
        .Set("color", json::Value::String(p.m_color));
    list.Push(std::move(item));
  }
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("positions")).Set("positions", std::move(list));
  return out;
}

json::Value SharingJson(SharingInfo const & s)
{
  auto const recipients = [](Manager::Recipients const & list)
  {
    auto out = json::Value::Array();
    for (auto const & [id, until] : list)
    {
      auto item = json::Value::Object();
      item.Set("id", json::Value::String(id)).Set("until", json::Value::Int(until));
      out.Push(std::move(item));
    }
    return out;
  };
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("sharing"))
      .Set("active", json::Value::Bool(s.m_active))
      .Set("live", json::Value::Bool(s.m_live))
      .Set("recipients", recipients(s.m_recipients))
      .Set("resumable", recipients(s.m_resumable));
  return out;
}

json::Value ConsentJson(ConsentRequest const & request)
{
  char const * const purposes[] = {"pairing", "viewing", "live_updates", "sending"};
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("consent"))
      .Set("url", json::Value::String(request.m_url))
      .Set("contact", json::Value::String(request.m_contactName))
      .Set("purpose", json::Value::String(purposes[static_cast<int>(request.m_purpose)]));
  return out;
}

json::Value LocationRequestJson(LocationRequest request)
{
  char const * const modes[] = {"Off", "Idle", "Live"};
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("location")).Set("mode", json::Value::String(modes[static_cast<int>(request)]));
  return out;
}

json::Value SettingsJson(Settings const & settings, bool readable)
{
  auto relays = json::Value::Array();
  for (auto const & url : settings.m_homeRelays)
    relays.Push(json::Value::String(url));
  auto approved = json::Value::Array();
  for (auto const & [url, contact] : settings.m_approved)
  {
    auto item = json::Value::Object();
    item.Set("url", json::Value::String(url)).Set("contact", json::Value::String(contact));
    approved.Push(std::move(item));
  }
  auto declined = json::Value::Array();
  for (auto const & [url, contact] : settings.m_declined)
  {
    auto item = json::Value::Object();
    item.Set("url", json::Value::String(url)).Set("contact", json::Value::String(contact));
    declined.Push(std::move(item));
  }
  auto colors = json::Value::Array();
  for (auto const & color : kDotColors)
  {
    auto item = json::Value::Object();
    item.Set("name", json::Value::String(std::string(color.m_name)))
        .Set("rgb", json::Value::Int(static_cast<int64_t>(color.m_rgba >> 8)));
    colors.Push(std::move(item));
  }
  auto defaults = json::Value::Array();
  for (auto const & url : kDefaultRelays)
    defaults.Push(json::Value::String(std::string(url)));
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("settings"))
      .Set("readable", json::Value::Bool(readable))
      .Set("name", json::Value::String(settings.m_name))
      .Set("relays", std::move(relays))
      .Set("approved", std::move(approved))
      .Set("declined", std::move(declined))
      .Set("default_relays", std::move(defaults))
      .Set("request_live", json::Value::Bool(settings.m_requestLive))
      .Set("allow_live", json::Value::Bool(settings.m_allowLive))
      .Set("low_battery_stop", json::Value::Int(settings.m_lowBatteryStop))
      .Set("color", json::Value::String(settings.m_color))
      .Set("dot_colors", std::move(colors));
  return out;
}
}  // namespace live_location
