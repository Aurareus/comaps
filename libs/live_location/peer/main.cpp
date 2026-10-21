// A desktop peer for live location (NLL v1): the core library driven by line commands on stdin, with
// every event as one JSON object per line on stdout. For cross-implementation tests against the
// Python reference over a local relay; ws:// only, and its keys are not protected.

#include "live_location/crypto/random.hpp"
#include "live_location/manager/manager.hpp"
#include "live_location/manager/views_json.hpp"
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

class Printer : public ManagerListener
{
public:
  void OnContacts(std::vector<ContactInfo> const & contacts) override { Print(ContactsJson(contacts)); }
  void OnPairing(PairingInfo const & pairing) override { Print(PairingJson(pairing)); }
  void OnPositions(std::vector<PositionInfo> const & positions) override { Print(PositionsJson(positions)); }
  void OnSharing(SharingInfo const & sharing) override { Print(SharingJson(sharing)); }
  void OnConsentNeeded(ConsentRequest const & request) override { Print(ConsentJson(request)); }
  void OnLocationRequest(LocationRequest request) override { Print(LocationRequestJson(request)); }
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
  if (command == "consent")  // consent <url> allow|notnow|refuse <contact>
  {
    Consent const consent = arg(1) == "allow" ? Consent::Allow : arg(1) == "notnow" ? Consent::NotNow : Consent::Refuse;
    manager.SetConsent(arg(0), consent, arg(2));
    return true;
  }
  if (command == "color")  // color [<name>]: none for each viewer's pick
    return manager.SetColor(arg(0));
  if (command == "lowbattery")
    return manager.SetLowBatteryStop(std::stoi(arg(0)));
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
  if (command == "settings")
  {
    Print(SettingsJson(manager.GetSettings(), manager.IsStarted()));
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
