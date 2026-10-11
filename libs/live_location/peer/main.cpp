// A desktop peer for live location (NLL v1): the core library driven by line commands on stdin, with
// every event as one JSON object per line on stdout. For cross-implementation tests against the
// Python reference over a local relay; ws:// only, and its keys are not protected.

#include "live_location/crypto/random.hpp"
#include "live_location/manager/manager.hpp"
#include "live_location/peer/plain_websocket.hpp"
#include "live_location/protocol/json.hpp"
#include "live_location/store/store.hpp"
#include "live_location/thread_executor.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
using namespace live_location;

std::mutex g_output;

void Print(json::Value const & value)
{
  std::lock_guard lock(g_output);
  std::cout << value.Dump() << std::endl;
}

json::Value Optional(std::optional<int64_t> const & value)
{
  return value ? json::Value::Int(*value) : json::Value();
}

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
        .Set("hidden", json::Value::Bool(c.m_hidden))
        .Set("shares_with_me", Optional(c.m_sharesWithMeUntil))
        .Set("i_share", Optional(c.m_iShareUntil))
        .Set("live_updates_off", json::Value::Bool(c.m_liveUpdatesOff));
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
        .Set("stale", json::Value::Bool(p.m_stale));
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

class Printer : public ManagerListener
{
public:
  void OnContacts(std::vector<ContactInfo> const & contacts) override { Print(ContactsJson(contacts)); }
  void OnPairing(PairingInfo const & pairing) override { Print(PairingJson(pairing)); }
  void OnPositions(std::vector<PositionInfo> const & positions) override { Print(PositionsJson(positions)); }
  void OnSharing(SharingInfo const & sharing) override { Print(SharingJson(sharing)); }
  void OnConsentNeeded(ConsentRequest const & request) override
  {
    char const * const purposes[] = {"pairing", "viewing", "live_updates", "sending"};
    auto out = json::Value::Object();
    out.Set("event", json::Value::String("consent"))
        .Set("url", json::Value::String(request.m_url))
        .Set("contact", json::Value::String(request.m_contactName))
        .Set("purpose", json::Value::String(purposes[static_cast<int>(request.m_purpose)]));
    Print(out);
  }
  void OnLocationRequest(LocationRequest request) override
  {
    char const * const modes[] = {"Off", "Idle", "Live"};
    auto out = json::Value::Object();
    out.Set("event", json::Value::String("location"))
        .Set("mode", json::Value::String(modes[static_cast<int>(request)]));
    Print(out);
  }
  void OnStoreError() override
  {
    auto out = json::Value::Object();
    out.Set("event", json::Value::String("store_error"));
    Print(out);
  }
};

void Result(std::string const & command, bool ok)
{
  auto out = json::Value::Object();
  out.Set("event", json::Value::String("result"))
      .Set("command", json::Value::String(command))
      .Set("ok", json::Value::Bool(ok));
  Print(out);
}

std::optional<std::string> IdOf(Manager & manager, std::string const & name)
{
  for (auto const & contact : manager.Contacts())
    if (contact.m_name == name)
      return contact.m_id;
  return {};
}

/// "name" or "name:seconds" (0 or none: until stopped) -> recipients.
std::optional<Manager::Recipients> ParseRecipients(Manager & manager, std::vector<std::string> const & args,
                                                   Executor const & executor)
{
  Manager::Recipients out;
  for (auto const & arg : args)
  {
    auto const colon = arg.find(':');
    auto const id = IdOf(manager, arg.substr(0, colon));
    if (!id)
      return {};
    int64_t const seconds = colon == std::string::npos ? 0 : std::stoll(arg.substr(colon + 1));
    out.emplace_back(*id, seconds == 0 ? 0 : executor.Now() + seconds);
  }
  return out;
}

bool Execute(Manager & manager, Executor const & executor, std::vector<std::string> const & words)
{
  std::string const & command = words[0];
  std::vector<std::string> const args(words.begin() + 1, words.end());
  auto const arg = [&](size_t i) { return i < args.size() ? args[i] : std::string(); };

  if (command == "name")
    return manager.SetName(arg(0));
  if (command == "relays")
    return manager.SetHomeRelays(args);
  if (command == "consent")
  {
    manager.SetConsent(arg(0), arg(1) == "allow", arg(2));
    return true;
  }
  if (command == "foreground")
  {
    manager.SetForeground(arg(0) == "on");
    return true;
  }
  if (command == "live")
  {
    manager.SetRequestLive(arg(0) == "on");
    manager.SetAllowLive(arg(0) == "on");
    return true;
  }
  if (command == "invite")
    return manager.CreateInvite(arg(0) == "link").has_value();
  if (command == "open")
  {
    auto const info = manager.OpenInvite(arg(0));
    if (info)
      Print(PairingJson(*info));
    return info.has_value();
  }
  if (command == "confirm")
  {
    manager.ConfirmCode(arg(0), arg(1) == "match");
    return true;
  }
  if (command == "decide")
  {
    manager.Decide(arg(0), arg(1) == "accept", arg(2) == "compared");
    return true;
  }
  if (command == "cancel")
  {
    manager.CancelPairing(arg(0));
    return true;
  }
  if (command == "share" || command == "change")
  {
    auto const recipients = ParseRecipients(manager, args, executor);
    if (!recipients)
      return false;
    return command == "share" ? manager.StartSharing(*recipients) : manager.ChangeSharing(*recipients);
  }
  if (command == "extend")
  {
    auto const id = IdOf(manager, arg(0));
    return id && manager.ExtendSharing(*id, executor.Now() + std::stoll(arg(1)));
  }
  if (command == "stop")
  {
    manager.StopSharing();
    return true;
  }
  if (command == "fix")
  {
    Location fix;
    fix.m_ts = executor.NowMs();
    fix.m_lat = std::stod(arg(0));
    fix.m_lon = std::stod(arg(1));
    fix.m_acc = args.size() > 2 ? std::stod(arg(2)) : 5.0;
    manager.OnLocation(fix);
    return true;
  }
  if (command == "battery")
  {
    manager.OnBatteryLevel(std::stoi(arg(0)));
    return true;
  }
  if (command == "verify")
  {
    auto const id = IdOf(manager, arg(0));
    if (id)
      manager.MarkVerified(*id);
    return id.has_value();
  }
  if (command == "delete")
  {
    auto const id = IdOf(manager, arg(0));
    if (id)
      manager.DeleteContact(*id);
    return id.has_value();
  }
  if (command == "contacts")
  {
    Print(ContactsJson(manager.Contacts()));
    return true;
  }
  if (command == "positions")
  {
    Print(PositionsJson(manager.Positions()));
    return true;
  }
  if (command == "sharing")
  {
    Print(SharingJson(manager.Sharing()));
    return true;
  }
  if (command == "pairings")
  {
    for (auto const & pairing : manager.Pairings())
      Print(PairingJson(pairing));
    return true;
  }
  if (command == "connections")
  {
    auto list = json::Value::Array();
    for (auto const & [url, scope] : manager.Pool().Connections())
      list.Push(json::Value::String(url + " " + scope));
    auto out = json::Value::Object();
    out.Set("event", json::Value::String("connections")).Set("connections", std::move(list));
    Print(out);
    return true;
  }
  return false;
}
}  // namespace

int main(int argc, char ** argv)
{
  std::string path = "live_location_peer.dat";
  for (int i = 1; i + 1 < argc; ++i)
    if (std::string(argv[i]) == "--state")
      path = argv[i + 1];
  std::remove(path.c_str());  // the keys live in memory only: every run starts afresh

  ThreadExecutor executor;
  peer::PlainTransport transport(executor);
  store::InsecureKeyWrapper keys;
  store::Store store(path, keys, crypto::SystemRng());
  Printer printer;
  std::unique_ptr<Manager> manager;
  executor.RunSync([&]
  {
    manager = std::make_unique<Manager>(executor, transport, store, crypto::SystemRng(), printer);
    Result("start", manager->Start());
  });

  std::string line;
  while (std::getline(std::cin, line))
  {
    std::istringstream stream(line);
    std::vector<std::string> words;
    for (std::string word; stream >> word;)
      words.push_back(word);
    if (words.empty() || words[0].front() == '#')
      continue;
    if (words[0] == "quit")
      break;
    if (words[0] == "sleep" && words.size() > 1)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(std::stoll(words[1])));
      Result("sleep", true);
      continue;
    }
    executor.RunSync([&]
    {
      bool ok = false;
      try
      {
        ok = Execute(*manager, executor, words);
      }
      catch (std::exception const &)
      {
        ok = false;  // e.g. a number that does not parse
      }
      Result(words[0], ok);
    });
  }
  executor.RunSync([&] { manager.reset(); });
  executor.Shutdown();
  std::remove(path.c_str());
  return 0;
}
