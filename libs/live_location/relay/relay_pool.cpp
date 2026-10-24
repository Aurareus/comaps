#include "live_location/relay/relay_pool.hpp"

#include "live_location/crypto/bytes.hpp"
#include "live_location/nostr/relay_message.hpp"
#include "live_location/protocol/common.hpp"

#include "base/logging.hpp"

#include <algorithm>
#include <limits>

namespace live_location::relay
{
namespace
{
size_t constexpr kPublishedKept = 64;  // per connection, for the echo check
}  // namespace

Scope EpochScope(int64_t epoch)
{
  return "e" + std::to_string(epoch);
}

Scope PairingScope(std::string const & pairingId)
{
  return "p" + pairingId;
}

class RelayPool::Listener : public SocketListener
{
public:
  Listener(RelayPool & pool, uint64_t id) : m_pool(pool), m_id(id) {}

  void OnOpen() override { m_pool.OnOpen(m_id); }
  void OnMessage(std::string const & text) override { m_pool.OnMessage(m_id, text); }
  void OnClosed(std::string const & reason) override { m_pool.OnClosed(m_id, reason); }

private:
  RelayPool & m_pool;
  uint64_t const m_id;
};

struct RelayPool::Connection
{
  uint64_t m_id = 0;
  std::string m_url;
  Scope m_scope;
  std::unique_ptr<Listener> m_listener;
  std::unique_ptr<Socket> m_socket;
  struct Req
  {
    SubscriptionId m_subscription = 0;
    std::vector<nostr::Filter> m_filters;          // as last sent: the events the relay may deliver for it
    std::vector<nostr::Filter> m_previousFilters;  // sent before, and still delivered for until the EOSE
    bool m_live = false;                           // the EOSE for the REQ as last sent has arrived
  };

  bool m_open = false;
  std::vector<std::string> m_queue;              // sent once open
  std::map<std::string, Req> m_reqs;             // REQ id -> subscription
  std::map<std::string, uint64_t> m_awaitingOk;  // event id -> publication
  // Published events that a live REQ here asks for: event id -> echo timeout, set once the relay accepts.
  std::map<std::string, Executor::TaskId> m_echoes;
  std::deque<std::string> m_publishedOrder;  // the latest events published here, which may come back
  std::unordered_set<std::string> m_published;
  size_t m_invalidEvents = 0;
  Executor::TaskId m_connectTimer = Executor::kNoTask;
  Executor::TaskId m_lingerTimer = Executor::kNoTask;
};

struct RelayPool::Subscription
{
  Scope m_scope;
  Relays m_urls;
  Placement m_placement = Placement::All;
  FiltersFn m_filters;
  EventFn m_onEvent;
  EoseFn m_onEose;
  std::map<std::string, std::string> m_active;  // url -> REQ id
  std::deque<std::string> m_seenOrder;
  std::unordered_set<std::string> m_seen;
  Executor::TaskId m_retryTimer = Executor::kNoTask;
};

struct RelayPool::Publication
{
  DoneFn m_done;
  std::map<std::string, Executor::TaskId> m_pending;  // url -> OK timeout
  bool m_reported = false;
};

RelayPool::RelayPool(Transport & transport, Executor & executor, crypto::Rng & rng, AllowFn isAllowed,
                     PoolConfig config)
  : m_transport(transport)
  , m_executor(executor)
  , m_rng(rng)
  , m_isAllowed(std::move(isAllowed))
  , m_config(config)
{}

RelayPool::~RelayPool()
{
  CloseAll();
  m_closed.clear();
}

Executor::TaskId RelayPool::Later(int64_t delayMs, std::function<void()> task)
{
  std::weak_ptr<int> alive = m_alive;
  return m_executor.PostDelayed(std::max<int64_t>(0, delayMs), [alive, task = std::move(task)]
  {
    if (!alive.expired())
      task();
  });
}

void RelayPool::Cancel(Executor::TaskId & id)
{
  if (id != Executor::kNoTask)
    m_executor.Cancel(id);
  id = Executor::kNoTask;
}

bool RelayPool::IsFailing(std::string const & url) const
{
  auto const it = m_health.find(url);
  return it != m_health.end() && m_executor.NowMs() < it->second.m_retryAtMs;
}

bool RelayPool::IsDeaf(std::string const & url) const
{
  auto const it = m_deaf.find(url);
  return it != m_deaf.end() && m_executor.NowMs() < it->second.m_retryAtMs;
}

std::optional<std::string> RelayPool::FirstReachable(Relays const & urls) const
{
  std::optional<std::string> deaf;
  for (auto const & url : urls)
  {
    if (!m_isAllowed(url) || IsFailing(url))
      continue;
    if (m_deaf.count(url) == 0)
      return url;
    if (!deaf)
      deaf = url;
  }
  return deaf;
}

std::vector<std::pair<std::string, Scope>> RelayPool::Connections() const
{
  std::vector<std::pair<std::string, Scope>> out;
  for (auto const & entry : m_connections)
    out.emplace_back(entry.second->m_url, entry.second->m_scope);
  return out;
}

std::vector<std::string> RelayPool::PlacementOf(SubscriptionId id) const
{
  std::vector<std::string> out;
  auto const it = m_subscriptions.find(id);
  if (it != m_subscriptions.end())
    for (auto const & active : it->second->m_active)
      out.push_back(active.first);
  return out;
}

RelayPool::Connection & RelayPool::GetConnection(std::string const & url, Scope const & scope)
{
  for (auto & entry : m_connections)
    if (entry.second->m_url == url && entry.second->m_scope == scope)
      return *entry.second;

  uint64_t const id = m_nextId++;
  auto connection = std::make_unique<Connection>();
  connection->m_id = id;
  connection->m_url = url;
  connection->m_scope = scope;
  connection->m_listener = std::make_unique<Listener>(*this, id);
  connection->m_socket = m_transport.Connect(url, *connection->m_listener);
  connection->m_connectTimer = Later(m_config.m_connectTimeoutMs, [this, id] { Fail(id, "connect timeout"); });
  Connection & out = *connection;
  m_connections.emplace(id, std::move(connection));
  return out;
}

RelayPool::Connection * RelayPool::FindConnection(uint64_t id)
{
  auto const it = m_connections.find(id);
  return it == m_connections.end() ? nullptr : it->second.get();
}

void RelayPool::Send(Connection & connection, std::string text)
{
  Touch(connection);
  if (connection.m_open)
    connection.m_socket->Send(text);
  else
    connection.m_queue.push_back(std::move(text));
}

void RelayPool::Touch(Connection & connection)
{
  Linger(connection);
}

void RelayPool::Linger(Connection & connection)
{
  Cancel(connection.m_lingerTimer);
  if (!connection.m_reqs.empty() || !connection.m_awaitingOk.empty())
    return;
  uint64_t const id = connection.m_id;
  connection.m_lingerTimer = Later(m_config.m_lingerMs, [this, id]
  {
    Connection * c = FindConnection(id);
    if (c != nullptr && c->m_reqs.empty() && c->m_awaitingOk.empty())
      Drop(id);
  });
}

RelayPool::SubscriptionId RelayPool::Subscribe(Scope scope, Relays urls, Placement placement, FiltersFn filters,
                                               EventFn onEvent, EoseFn onEose)
{
  SubscriptionId const id = m_nextId++;
  auto subscription = std::make_unique<Subscription>();
  subscription->m_scope = std::move(scope);
  subscription->m_urls = std::move(urls);
  subscription->m_placement = placement;
  subscription->m_filters = std::move(filters);
  subscription->m_onEvent = std::move(onEvent);
  subscription->m_onEose = std::move(onEose);
  m_subscriptions.emplace(id, std::move(subscription));
  Place(id);
  return id;
}

void RelayPool::Place(SubscriptionId id)
{
  auto const it = m_subscriptions.find(id);
  if (it == m_subscriptions.end())
    return;
  Subscription & subscription = *it->second;
  Cancel(subscription.m_retryTimer);

  std::vector<std::string> targets;
  std::optional<std::string> deaf;   // listened on only if no other relay can be
  std::optional<std::string> trial;  // listened on alongside the relay found
  int64_t retryAt = std::numeric_limits<int64_t>::max();
  for (auto const & url : subscription.m_urls)
  {
    if (!m_isAllowed(url) || std::find(targets.begin(), targets.end(), url) != targets.end())
      continue;
    if (IsFailing(url))
    {
      retryAt = std::min(retryAt, m_health[url].m_retryAtMs);
      continue;
    }
    if (auto const d = m_deaf.find(url); subscription.m_placement == Placement::FirstReachable && d != m_deaf.end())
    {
      // It accepts events without delivering them. Once its back-off is over it is tried again, but
      // next to a relay that delivers, until an event comes back over it (and it is the listening relay
      // again) or one does not (and its back-off doubles): only something published can tell.
      if (m_executor.NowMs() < d->second.m_retryAtMs)
      {
        retryAt = std::min(retryAt, d->second.m_retryAtMs);
        if (!deaf)
          deaf = url;
      }
      else if (!trial)
      {
        trial = url;
      }
      continue;
    }
    targets.push_back(url);
    if (subscription.m_placement == Placement::FirstReachable)
      break;
  }
  if (trial)
    targets.push_back(*trial);
  if (targets.empty() && deaf)
    targets.push_back(*deaf);

  std::vector<std::string> stale;
  for (auto const & active : subscription.m_active)
    if (std::find(targets.begin(), targets.end(), active.first) == targets.end())
      stale.push_back(active.first);
  for (auto const & url : stale)
    Detach(subscription, url);

  for (auto const & url : targets)
  {
    if (subscription.m_active.count(url) != 0)
      continue;
    Connection & connection = GetConnection(url, subscription.m_scope);
    std::string const reqId = ToHex(m_rng.GetBytes(8));  // fresh per REQ: ids must not link connections
    subscription.m_active.emplace(url, reqId);
    auto filters = subscription.m_filters();
    std::string text = nostr::ReqMessage(reqId, filters);
    connection.m_reqs.emplace(reqId, Connection::Req{id, std::move(filters), {}, false});
    Send(connection, std::move(text));
  }

  // A failing relay that the subscription should use (all of them, or an earlier one than the current
  // listening relay) is tried again when its back-off is over.
  if (retryAt != std::numeric_limits<int64_t>::max())
    subscription.m_retryTimer = Later(retryAt - m_executor.NowMs(), [this, id] { Place(id); });
}

void RelayPool::PlaceAllUsing(std::string const & url)
{
  std::vector<SubscriptionId> ids;
  for (auto const & entry : m_subscriptions)
  {
    auto const & urls = entry.second->m_urls;
    if (std::find(urls.begin(), urls.end(), url) != urls.end())
      ids.push_back(entry.first);
  }
  for (auto const id : ids)
    Place(id);
}

void RelayPool::Detach(Subscription & subscription, std::string const & url)
{
  auto const active = subscription.m_active.find(url);
  if (active == subscription.m_active.end())
    return;
  std::string const reqId = active->second;
  subscription.m_active.erase(active);
  for (auto & entry : m_connections)
  {
    Connection & connection = *entry.second;
    if (connection.m_url != url || connection.m_scope != subscription.m_scope)
      continue;
    if (connection.m_reqs.erase(reqId) != 0)
    {
      ForgetEchoes(connection);
      if (connection.m_open)
        connection.m_socket->Send(nostr::CloseMessage(reqId));
      Linger(connection);
    }
  }
}

void RelayPool::Refresh(SubscriptionId id)
{
  auto const it = m_subscriptions.find(id);
  if (it == m_subscriptions.end())
    return;
  Subscription & subscription = *it->second;
  auto const filters = subscription.m_filters();
  for (auto const & [url, reqId] : subscription.m_active)
  {
    for (auto & entry : m_connections)
    {
      Connection & connection = *entry.second;
      if (connection.m_url != url || connection.m_scope != subscription.m_scope)
        continue;
      auto const req = connection.m_reqs.find(reqId);
      if (req == connection.m_reqs.end())
        continue;
      // Until the relay's EOSE for the new REQ, it may still deliver what the old one asked for.
      auto & previous = req->second.m_previousFilters;
      previous.insert(previous.end(), req->second.m_filters.begin(), req->second.m_filters.end());
      req->second.m_filters = filters;
      req->second.m_live = false;
      ForgetEchoes(connection);
      Send(connection, nostr::ReqMessage(reqId, filters));
    }
  }
}

void RelayPool::Unsubscribe(SubscriptionId id)
{
  auto const it = m_subscriptions.find(id);
  if (it == m_subscriptions.end())
    return;
  Subscription & subscription = *it->second;
  Cancel(subscription.m_retryTimer);
  std::vector<std::string> urls;
  for (auto const & active : subscription.m_active)
    urls.push_back(active.first);
  for (auto const & url : urls)
    Detach(subscription, url);
  m_subscriptions.erase(it);
}

void RelayPool::Publish(Scope const & scope, Relays const & urls, nostr::Event const & event, DoneFn done)
{
  uint64_t const id = m_nextId++;
  auto publication = std::make_unique<Publication>();
  publication->m_done = std::move(done);
  Publication & p = *publication;
  m_publications.emplace(id, std::move(publication));

  std::string const text = nostr::EventMessage(event);
  for (auto const & url : urls)
  {
    if (!m_isAllowed(url) || IsFailing(url) || p.m_pending.count(url) != 0)
      continue;
    Connection & connection = GetConnection(url, scope);
    connection.m_awaitingOk[event.m_id] = id;
    if (connection.m_published.insert(event.m_id).second)
    {
      connection.m_publishedOrder.push_back(event.m_id);
      if (connection.m_publishedOrder.size() > kPublishedKept)
      {
        connection.m_published.erase(connection.m_publishedOrder.front());
        connection.m_publishedOrder.pop_front();
      }
    }
    for (auto const & req : connection.m_reqs)
      if (req.second.m_live && nostr::MatchesAny(req.second.m_filters, event))
        connection.m_echoes.emplace(event.m_id, Executor::kNoTask);
    int64_t const timeout = m_config.m_okTimeoutMs + (connection.m_open ? 0 : m_config.m_connectTimeoutMs);
    uint64_t const connectionId = connection.m_id;
    p.m_pending[url] = Later(timeout, [this, id, url, connectionId]
    {
      if (FindConnection(connectionId) != nullptr)
        Fail(connectionId, "no OK");  // a dead connection: this fails the publication there too
      else
        OnPublishResult(id, url, false);
    });
    Send(connection, text);
  }

  if (p.m_pending.empty())
  {
    DoneFn d = std::move(p.m_done);
    m_publications.erase(id);
    if (d)
    {
      std::weak_ptr<int> alive = m_alive;
      m_executor.Post([alive, d = std::move(d)]
      {
        if (!alive.expired())
          d(false);
      });
    }
  }
}

void RelayPool::OnPublishResult(uint64_t publicationId, std::string const & url, bool accepted)
{
  auto const it = m_publications.find(publicationId);
  if (it == m_publications.end())
    return;
  Publication & publication = *it->second;
  auto const pending = publication.m_pending.find(url);
  if (pending == publication.m_pending.end())
    return;
  Cancel(pending->second);
  publication.m_pending.erase(pending);

  DoneFn done;
  bool delivered = false;
  if (!publication.m_reported && (accepted || publication.m_pending.empty()))
  {
    publication.m_reported = true;
    delivered = accepted;
    done = publication.m_done;
  }
  if (publication.m_pending.empty())
    m_publications.erase(it);
  if (done)
    done(delivered);
}

void RelayPool::OnEvent(Connection & connection, std::string const & reqId, nostr::Event const & event)
{
  auto const req = connection.m_reqs.find(reqId);
  if (req == connection.m_reqs.end())
    return;
  auto const it = m_subscriptions.find(req->second.m_subscription);
  if (it == m_subscriptions.end())
    return;
  Subscription & subscription = *it->second;
  // An event this connection published, delivered back as it arrived (after the EOSE, so not a stored
  // copy): the relay delivers what it accepts. Noted before the deduplication, since another relay's
  // copy may have come first.
  if (req->second.m_live && connection.m_published.count(event.m_id) != 0)
    OnEcho(connection, event.m_id);
  if (subscription.m_seen.count(event.m_id) != 0)
    return;  // already delivered by another relay
  // Only a verified event the REQ asked for counts as seen: a relay that sends a broken or altered
  // copy first cannot keep the intact one from arriving through another relay (spec §11), and junk
  // costs the app no more than this check. A relay that keeps sending it counts as failing.
  if (!nostr::MatchesAny(req->second.m_filters, event))
  {
    // The REQ was sent again with other filters: until its EOSE, the old ones may still be answered.
    if (nostr::MatchesAny(req->second.m_previousFilters, event))
      return;
    if (++connection.m_invalidEvents > m_config.m_maxInvalidEvents)
      Fail(connection.m_id, "invalid events");
    return;
  }
  if (!nostr::Verify(event))
  {
    if (++connection.m_invalidEvents > m_config.m_maxInvalidEvents)
      Fail(connection.m_id, "invalid events");
    return;
  }
  subscription.m_seen.insert(event.m_id);
  subscription.m_seenOrder.push_back(event.m_id);
  if (subscription.m_seenOrder.size() > m_config.m_dedupe)
  {
    subscription.m_seen.erase(subscription.m_seenOrder.front());
    subscription.m_seenOrder.pop_front();
  }
  EventFn const onEvent = subscription.m_onEvent;  // the callback may unsubscribe
  onEvent(event);
}

void RelayPool::OnOpen(uint64_t connectionId)
{
  Connection * connection = FindConnection(connectionId);
  if (connection == nullptr)
    return;
  Cancel(connection->m_connectTimer);
  connection->m_open = true;
  m_health.erase(connection->m_url);
  std::vector<std::string> queue = std::move(connection->m_queue);
  connection->m_queue.clear();
  for (auto const & text : queue)
    connection->m_socket->Send(text);
  Linger(*connection);
  // The relay is reachable again: subscriptions that skipped it come back.
  std::string const url = connection->m_url;
  PlaceAllUsing(url);
  if (m_onConnected)
    m_onConnected(url);
}

void RelayPool::OnMessage(uint64_t connectionId, std::string const & text)
{
  Connection * connection = FindConnection(connectionId);
  if (connection == nullptr)
    return;
  Touch(*connection);
  auto const message = nostr::ParseRelayMessage(text);
  if (!message)
    return;

  switch (message->m_type)
  {
  case nostr::RelayMessage::Type::Event:
  {
    if (message->m_event)
      OnEvent(*connection, message->m_subscriptionId, *message->m_event);
    break;
  }
  case nostr::RelayMessage::Type::Ok:
  {
    auto const awaiting = connection->m_awaitingOk.find(message->m_eventId);
    if (awaiting == connection->m_awaitingOk.end())
      break;
    if (auto const echo = connection->m_echoes.find(message->m_eventId); echo != connection->m_echoes.end())
    {
      // A refused event comes back to no one, and neither does one the relay already had.
      if (!message->m_accepted || message->m_message.starts_with("duplicate:"))
      {
        connection->m_echoes.erase(echo);
      }
      else if (echo->second == Executor::kNoTask)
      {
        uint64_t const connectionId = connection->m_id;
        std::string const eventId = message->m_eventId;
        echo->second =
            Later(m_config.m_echoTimeoutMs, [this, connectionId, eventId] { OnEchoMissing(connectionId, eventId); });
      }
    }
    uint64_t const publicationId = awaiting->second;
    std::string const url = connection->m_url;
    connection->m_awaitingOk.erase(awaiting);
    Linger(*connection);
    OnPublishResult(publicationId, url, message->m_accepted);
    break;
  }
  case nostr::RelayMessage::Type::Eose:
  {
    auto const req = connection->m_reqs.find(message->m_subscriptionId);
    if (req == connection->m_reqs.end())
      break;
    req->second.m_live = true;
    req->second.m_previousFilters.clear();
    auto const subscription = m_subscriptions.find(req->second.m_subscription);
    if (subscription != m_subscriptions.end() && subscription->second->m_onEose)
    {
      EoseFn const onEose = subscription->second->m_onEose;
      onEose(connection->m_url);
    }
    break;
  }
  case nostr::RelayMessage::Type::Closed:
  {
    auto const req = connection->m_reqs.find(message->m_subscriptionId);
    if (req == connection->m_reqs.end())
      break;
    SubscriptionId const id = req->second.m_subscription;
    connection->m_reqs.erase(req);
    ForgetEchoes(*connection);
    LOG(LINFO, ("Relay closed a subscription:", connection->m_url, message->m_message));
    auto const subscription = m_subscriptions.find(id);
    if (subscription != m_subscriptions.end())
    {
      subscription->second->m_active.erase(connection->m_url);
      Cancel(subscription->second->m_retryTimer);
      subscription->second->m_retryTimer = Later(m_config.m_closedRetryMs, [this, id] { Place(id); });
    }
    Linger(*connection);
    break;
  }
  case nostr::RelayMessage::Type::Notice: LOG(LDEBUG, ("Relay notice:", connection->m_url, message->m_message)); break;
  }
}

void RelayPool::OnClosed(uint64_t connectionId, std::string const & reason)
{
  Fail(connectionId, reason);
}

void RelayPool::OnEcho(Connection & connection, std::string const & eventId)
{
  m_echoing.insert(connection.m_url);
  if (m_onEchoed)
    m_onEchoed(connection.m_url);
  if (auto const echo = connection.m_echoes.find(eventId); echo != connection.m_echoes.end())
  {
    Cancel(echo->second);
    connection.m_echoes.erase(echo);
  }
  if (m_deaf.erase(connection.m_url) != 0)
  {
    // A relay on trial delivers again: listening subscriptions come back to it.
    std::string const url = connection.m_url;
    Later(0, [this, url] { PlaceAllUsing(url); });
  }
}

void RelayPool::ForgetEchoes(Connection & connection)
{
  // The REQs changed: what they ask for may no longer come back. Nothing is judged on it.
  for (auto & echo : connection.m_echoes)
    Cancel(echo.second);
  connection.m_echoes.clear();
}

void RelayPool::OnEchoMissing(uint64_t connectionId, std::string const & eventId)
{
  Connection * connection = FindConnection(connectionId);
  if (connection == nullptr)
    return;
  auto const echo = connection->m_echoes.find(eventId);
  if (echo == connection->m_echoes.end())
    return;
  connection->m_echoes.erase(echo);
  std::string const url = connection->m_url;
  // A relay that has never sent an event back is unknown, not deaf. Otherwise one miss decides.
  if (m_echoing.count(url) == 0)
    return;
  ForgetEchoes(*connection);

  Deafness & deafness = m_deaf[url];
  deafness.m_misses = std::min(deafness.m_misses + 1, 20);
  int64_t backoff = m_config.m_deafBackoffMinMs << (deafness.m_misses - 1);
  backoff = std::min(backoff, m_config.m_deafBackoffMaxMs);
  backoff = backoff * (80 + RandomBelow(m_rng, 41)) / 100;
  deafness.m_retryAtMs = m_executor.NowMs() + backoff;
  LOG(LINFO, ("Relay accepts events without delivering them:", url));
  PlaceAllUsing(url);  // a listening subscription moves to the next relay
}

void RelayPool::Fail(uint64_t connectionId, std::string const & reason)
{
  auto const it = m_connections.find(connectionId);
  if (it == m_connections.end())
    return;
  std::unique_ptr<Connection> connection = std::move(it->second);
  m_connections.erase(it);
  std::string const url = connection->m_url;
  LOG(LINFO, ("Relay connection failed:", url, reason));

  Health & health = m_health[url];
  health.m_failures = std::min(health.m_failures + 1, 30);
  int64_t backoff = m_config.m_backoffMinMs << std::min(health.m_failures - 1, 20);
  backoff = std::min(backoff, m_config.m_backoffMaxMs);
  backoff = backoff * (80 + RandomBelow(m_rng, 41)) / 100;  // +-20 %, so that clients do not retry in step
  health.m_retryAtMs = m_executor.NowMs() + backoff;

  Cancel(connection->m_connectTimer);
  Cancel(connection->m_lingerTimer);
  connection->m_socket->Close();
  std::vector<SubscriptionId> subscriptions;
  for (auto const & req : connection->m_reqs)
    subscriptions.push_back(req.second.m_subscription);
  std::vector<uint64_t> publications;
  for (auto const & awaiting : connection->m_awaitingOk)
    publications.push_back(awaiting.second);
  m_closed.push_back(std::move(connection));
  std::weak_ptr<int> alive = m_alive;
  m_executor.Post([this, alive]
  {
    if (!alive.expired())
      m_closed.clear();
  });

  for (auto const id : subscriptions)
  {
    auto const s = m_subscriptions.find(id);
    if (s != m_subscriptions.end())
      s->second->m_active.erase(url);
  }
  for (auto const id : publications)
    OnPublishResult(id, url, false);
  for (auto const id : subscriptions)
    Place(id);
}

void RelayPool::Drop(uint64_t connectionId)
{
  auto const it = m_connections.find(connectionId);
  if (it == m_connections.end())
    return;
  std::unique_ptr<Connection> connection = std::move(it->second);
  m_connections.erase(it);
  Cancel(connection->m_connectTimer);
  Cancel(connection->m_lingerTimer);
  connection->m_socket->Close();
  m_closed.push_back(std::move(connection));
  std::weak_ptr<int> alive = m_alive;
  m_executor.Post([this, alive]
  {
    if (!alive.expired())
      m_closed.clear();
  });
}

void RelayPool::CloseAll()
{
  for (auto & entry : m_connections)
  {
    Cancel(entry.second->m_connectTimer);
    Cancel(entry.second->m_lingerTimer);
    entry.second->m_socket->Close();
    m_closed.push_back(std::move(entry.second));
  }
  m_connections.clear();
  for (auto & entry : m_subscriptions)
    Cancel(entry.second->m_retryTimer);
  m_subscriptions.clear();
  for (auto & entry : m_publications)
    for (auto & pending : entry.second->m_pending)
      Cancel(pending.second);
  m_publications.clear();
}
}  // namespace live_location::relay
