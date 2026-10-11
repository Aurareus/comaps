#include "live_location/live_location_tests/fake_relay.hpp"

#include "live_location/protocol/json.hpp"

#include <algorithm>

#include <jansson.h>

namespace live_location_tests
{
using namespace live_location;

void VirtualExecutor::Post(Task task)
{
  PostDelayed(0, std::move(task));
}

Executor::TaskId VirtualExecutor::PostDelayed(int64_t delayMs, Task task)
{
  TaskId const id = m_nextId++;
  Key const key{m_nowMs + std::max<int64_t>(0, delayMs), m_order++};
  m_queue.emplace(key, std::make_pair(id, std::move(task)));
  m_index.emplace(id, key);
  return id;
}

void VirtualExecutor::Cancel(TaskId id)
{
  auto const it = m_index.find(id);
  if (it == m_index.end())
    return;
  m_queue.erase(it->second);
  m_index.erase(it);
}

void VirtualExecutor::RunUntil(int64_t untilMs)
{
  while (!m_queue.empty() && m_queue.begin()->first.first <= untilMs)
  {
    auto node = m_queue.extract(m_queue.begin());
    m_index.erase(node.mapped().first);
    m_nowMs = std::max(m_nowMs, node.key().first);
    node.mapped().second();
  }
  m_nowMs = std::max(m_nowMs, untilMs);
}

struct FakeRelay::Link
{
  uint64_t m_id = 0;
  relay::SocketListener * m_listener = nullptr;
  bool m_clientClosed = false;  // no more events to the listener
  bool m_relayClosed = false;   // the relay ignores this link
  std::map<std::string, std::vector<nostr::Filter>> m_subscriptions;
};

namespace
{
class FakeSocket : public relay::Socket
{
public:
  FakeSocket(VirtualExecutor & executor, FakeRelay * relay, std::shared_ptr<FakeRelay::Link> link)
    : m_executor(executor)
    , m_relay(relay)
    , m_link(std::move(link))
  {}

  ~FakeSocket() override { Close(); }

  void Send(std::string const & text) override
  {
    if (m_relay == nullptr || m_link->m_clientClosed)
      return;
    FakeRelay * relay = m_relay;
    auto link = m_link;
    m_executor.PostDelayed(relay->m_latencyMs, [relay, link, text]
    {
      if (!link->m_clientClosed && !link->m_relayClosed)
        relay->Receive(link, text);
    });
  }

  void Close() override { m_link->m_clientClosed = true; }

private:
  VirtualExecutor & m_executor;
  FakeRelay * m_relay;
  std::shared_ptr<FakeRelay::Link> m_link;
};

std::string Quoted(std::string const & s)
{
  return json::Value::String(s).Dump();
}

std::vector<std::string> Strings(json_t const * array)
{
  std::vector<std::string> out;
  for (size_t i = 0; i < json_array_size(array); ++i)
    if (json_t const * v = json_array_get(array, i); json_is_string(v))
      out.emplace_back(json_string_value(v));
  return out;
}

nostr::Filter ParseFilter(json_t const * object)
{
  nostr::Filter filter;
  json_t const * kinds = json_object_get(object, "kinds");
  for (size_t i = 0; i < json_array_size(kinds); ++i)
    filter.m_kinds.push_back(json_integer_value(json_array_get(kinds, i)));
  filter.m_authors = Strings(json_object_get(object, "authors"));
  filter.m_pTags = Strings(json_object_get(object, "#p"));
  if (json_t const * since = json_object_get(object, "since"); json_is_integer(since))
    filter.m_since = json_integer_value(since);
  return filter;
}
}  // namespace

bool Matches(nostr::Filter const & filter, nostr::Event const & event)
{
  auto const has = [](auto const & values, auto const & v)
  { return values.empty() || std::find(values.begin(), values.end(), v) != values.end(); };
  if (!has(filter.m_kinds, event.m_kind) || !has(filter.m_authors, event.m_pubkey))
    return false;
  if (filter.m_since && event.m_createdAt < *filter.m_since)
    return false;
  if (!filter.m_pTags.empty())
  {
    bool found = false;
    for (auto const & tag : event.m_tags)
      if (tag.size() >= 2 && tag[0] == "p" && has(filter.m_pTags, tag[1]))
        found = true;
    if (!found)
      return false;
  }
  return true;
}

FakeRelay & FakeTransport::Add(std::string const & url)
{
  auto & relay = m_relays[url];
  relay = std::make_unique<FakeRelay>(m_executor, url);
  return *relay;
}

FakeRelay * FakeTransport::Find(std::string const & url)
{
  auto const it = m_relays.find(url);
  return it == m_relays.end() ? nullptr : it->second.get();
}

std::unique_ptr<relay::Socket> FakeTransport::Connect(std::string const & url, relay::SocketListener & listener)
{
  ++m_attempts[url];
  if (FakeRelay * relay = Find(url))
    return relay->Accept(listener);
  auto link = std::make_shared<FakeRelay::Link>();
  link->m_listener = &listener;
  m_executor.PostDelayed(40, [link]
  {
    if (!link->m_clientClosed)
      link->m_listener->OnClosed("unknown host");
  });
  return std::make_unique<FakeSocket>(m_executor, nullptr, link);
}

std::unique_ptr<relay::Socket> FakeRelay::Accept(relay::SocketListener & listener)
{
  auto link = std::make_shared<Link>();
  link->m_id = m_nextLink++;
  link->m_listener = &listener;
  if (m_down)
  {
    link->m_relayClosed = true;
    m_executor.PostDelayed(m_latencyMs, [link]
    {
      if (!link->m_clientClosed)
        link->m_listener->OnClosed("connection refused");
    });
    return std::make_unique<FakeSocket>(m_executor, nullptr, link);
  }
  m_links.push_back(link);
  m_executor.PostDelayed(m_latencyMs, [link]
  {
    if (!link->m_clientClosed && !link->m_relayClosed)
      link->m_listener->OnOpen();
  });
  return std::make_unique<FakeSocket>(m_executor, this, link);
}

void FakeRelay::SetDown(bool down)
{
  m_down = down;
  if (down)
    DropConnections();
}

void FakeRelay::DropConnections()
{
  for (auto const & link : m_links)
  {
    if (link->m_relayClosed)
      continue;
    link->m_relayClosed = true;
    m_executor.PostDelayed(m_latencyMs, [link]
    {
      if (!link->m_clientClosed)
        link->m_listener->OnClosed("dropped by the relay");
    });
  }
  m_links.clear();
}

size_t FakeRelay::OpenConnections() const
{
  return std::count_if(m_links.begin(), m_links.end(),
                       [](auto const & link) { return !link->m_clientClosed && !link->m_relayClosed; });
}

std::vector<nostr::Event> FakeRelay::Stored() const
{
  std::vector<nostr::Event> out;
  for (auto const & event : m_events)
    if (!Expired(event))
      out.push_back(event);
  return out;
}

bool FakeRelay::Expired(nostr::Event const & event) const
{
  auto const expiration = event.TagValue("expiration");
  return expiration && std::stoll(*expiration) <= m_executor.Now();
}

void FakeRelay::SendTo(std::shared_ptr<Link> const & link, std::string text)
{
  m_executor.PostDelayed(m_latencyMs, [link, text = std::move(text)]
  {
    if (!link->m_clientClosed)
      link->m_listener->OnMessage(text);
  });
}

void FakeRelay::Store(nostr::Event const & event)
{
  if (event.m_kind >= 20000 && event.m_kind < 30000)
    return;  // ephemeral
  if (event.m_kind >= 30000 && event.m_kind < 40000)
  {
    std::string const d = event.TagValue("d").value_or("");
    for (auto & stored : m_events)
    {
      if (stored.m_pubkey == event.m_pubkey && stored.m_kind == event.m_kind && stored.TagValue("d").value_or("") == d)
      {
        if (event.m_createdAt > stored.m_createdAt ||
            (event.m_createdAt == stored.m_createdAt && event.m_id < stored.m_id))
        {
          stored = event;
        }
        return;
      }
    }
  }
  m_events.push_back(event);
}

void FakeRelay::Forward(nostr::Event const & event)
{
  for (auto const & link : m_links)
  {
    if (link->m_clientClosed || link->m_relayClosed)
      continue;
    for (auto const & [id, filters] : link->m_subscriptions)
    {
      if (std::none_of(filters.begin(), filters.end(), [&](auto const & f) { return Matches(f, event); }))
        continue;
      std::string const message = "[\"EVENT\"," + Quoted(id) + "," + nostr::ToJson(event) + "]";
      SendTo(link, message);
      if (m_duplicate)
        SendTo(link, message);
    }
  }
}

void FakeRelay::Inject(nostr::Event const & event)
{
  Store(event);
  Forward(event);
}

void FakeRelay::CloseSubscriptions(std::string const & reason)
{
  for (auto const & link : m_links)
  {
    for (auto const & entry : link->m_subscriptions)
      SendTo(link, "[\"CLOSED\"," + Quoted(entry.first) + "," + Quoted(reason) + "]");
    link->m_subscriptions.clear();
  }
}

void FakeRelay::Receive(std::shared_ptr<Link> const & link, std::string const & text)
{
  m_received[link->m_id].push_back(text);
  if (m_silent)
    return;
  json_error_t error;
  json_t * root = json_loadb(text.data(), text.size(), 0, &error);
  if (root == nullptr || !json_is_array(root) || !json_is_string(json_array_get(root, 0)))
  {
    if (root != nullptr)
      json_decref(root);
    SendTo(link, "[\"NOTICE\",\"could not parse\"]");
    return;
  }
  std::string const type = json_string_value(json_array_get(root, 0));
  if (type == "EVENT")
  {
    auto const event = nostr::FromJson(json_array_get(root, 1));
    std::string const id = event ? event->m_id : std::string(64, '0');
    if (!event || !nostr::Verify(*event))
      SendTo(link, "[\"OK\"," + Quoted(id) + ",false,\"invalid: bad event\"]");
    else if (Expired(*event))
      SendTo(link, "[\"OK\"," + Quoted(id) + ",false,\"invalid: event has expired\"]");
    else if (m_refuse)
      SendTo(link, "[\"OK\"," + Quoted(id) + ",false,\"blocked: test\"]");
    else
    {
      Store(*event);
      SendTo(link, "[\"OK\"," + Quoted(id) + ",true,\"\"]");
      Forward(*event);
    }
  }
  else if (type == "REQ" && json_is_string(json_array_get(root, 1)))
  {
    std::string const id = json_string_value(json_array_get(root, 1));
    std::vector<nostr::Filter> filters;
    for (size_t i = 2; i < json_array_size(root); ++i)
      filters.push_back(ParseFilter(json_array_get(root, i)));
    link->m_subscriptions[id] = filters;
    for (auto const & event : m_events)
      if (!Expired(event) &&
          std::any_of(filters.begin(), filters.end(), [&](auto const & f) { return Matches(f, event); }))
        SendTo(link, "[\"EVENT\"," + Quoted(id) + "," + nostr::ToJson(event) + "]");
    SendTo(link, "[\"EOSE\"," + Quoted(id) + "]");
  }
  else if (type == "CLOSE" && json_is_string(json_array_get(root, 1)))
  {
    link->m_subscriptions.erase(json_string_value(json_array_get(root, 1)));
  }
  json_decref(root);
}
}  // namespace live_location_tests
