#pragma once

#include "live_location/crypto/random.hpp"
#include "live_location/executor.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/nostr/filter.hpp"
#include "live_location/protocol/messages.hpp"
#include "live_location/relay/transport.hpp"

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// Connections to relays (design doc §8.1, §10.3; spec §11).
namespace live_location::relay
{
/// What may travel over one connection. A connection carries the keys of one epoch only (spec §11), so
/// every subscription and publication names its scope: the epoch of its keys, or a pairing, which gets
/// connections of its own.
using Scope = std::string;
Scope EpochScope(int64_t epoch);
Scope PairingScope(std::string const & pairingId);

struct PoolConfig
{
  int64_t m_okTimeoutMs = 10'000;       // no OK in this time: the publish failed there, and the connection is dead
  int64_t m_connectTimeoutMs = 15'000;  // not open in this time: the connection failed
  int64_t m_lingerMs = 60'000;          // a connection used only to publish closes after this long without traffic
  int64_t m_backoffMinMs = 1'000;       // a failing relay is retried after this, doubling up to the maximum
  int64_t m_backoffMaxMs = 300'000;
  int64_t m_closedRetryMs = 30'000;  // a subscription the relay CLOSED is sent again after this
  size_t m_dedupe = 4096;            // event ids remembered per subscription
};

enum class Placement
{
  All,             // on every relay of the list that is not failing
  FirstReachable,  // on the first relay of the list that is not failing: a listening relay (design doc D17)
};

/// All relay traffic, on the executor's thread. A relay that fails (it cannot be reached, drops the
/// connection, or does not answer a publish within m_okTimeoutMs) backs off and is skipped until it
/// has recovered or its back-off is over. Subscriptions move to other relays meanwhile and come back.
/// Connections open when something needs them and close when nothing does: a connection without
/// subscriptions closes after m_lingerMs without traffic. Nothing connects to a relay that `isAllowed`
/// refuses (relay consent, spec §11).
class RelayPool
{
public:
  using SubscriptionId = uint64_t;
  using FiltersFn = std::function<std::vector<nostr::Filter>()>;
  using EventFn = std::function<void(nostr::Event const & event)>;
  using EoseFn = std::function<void(std::string const & url)>;
  using DoneFn = std::function<void(bool delivered)>;
  using AllowFn = std::function<bool(std::string const & url)>;

  RelayPool(Transport & transport, Executor & executor, crypto::Rng & rng, AllowFn isAllowed, PoolConfig config = {});
  ~RelayPool();

  RelayPool(RelayPool const &) = delete;
  RelayPool & operator=(RelayPool const &) = delete;

  /// A subscription on `urls`. `filters` is called whenever the REQ is (re)sent. Events arrive once,
  /// whichever relays deliver them. `onEose` runs once per relay and REQ.
  SubscriptionId Subscribe(Scope scope, Relays urls, Placement placement, FiltersFn filters, EventFn onEvent,
                           EoseFn onEose = {});
  /// Sends the REQs again with the current filters.
  void Refresh(SubscriptionId id);
  void Unsubscribe(SubscriptionId id);

  /// Sends `event` to every relay of `urls` that is not failing. `done(true)` follows the first OK that
  /// accepts it, `done(false)` the last refusal, failure or timeout when none accepted it.
  void Publish(Scope const & scope, Relays const & urls, nostr::Event const & event, DoneFn done = {});

  /// Closes every connection and forgets every subscription and publication, without callbacks.
  void CloseAll();

  /// Whether `url` is backing off after a failure.
  bool IsFailing(std::string const & url) const;
  /// The first relay of `urls` that is allowed and not failing.
  std::optional<std::string> FirstReachable(Relays const & urls) const;

  /// (url, scope) of every connection that is open or opening.
  std::vector<std::pair<std::string, Scope>> Connections() const;
  /// The relays a subscription currently runs on.
  std::vector<std::string> PlacementOf(SubscriptionId id) const;

private:
  class Listener;
  struct Connection;
  struct Subscription;
  struct Publication;

  struct Health
  {
    int m_failures = 0;
    int64_t m_retryAtMs = 0;
  };

  Connection & GetConnection(std::string const & url, Scope const & scope);
  Connection * FindConnection(uint64_t id);
  void Send(Connection & connection, std::string text);
  void Place(SubscriptionId id);
  void PlaceAllUsing(std::string const & url);
  void Detach(Subscription & subscription, std::string const & url);
  void Fail(uint64_t connectionId, std::string const & reason);
  void Drop(uint64_t connectionId);
  void Touch(Connection & connection);
  void Linger(Connection & connection);
  void OnPublishResult(uint64_t publicationId, std::string const & url, bool accepted);
  void Deliver(SubscriptionId id, nostr::Event const & event);

  void OnOpen(uint64_t connectionId);
  void OnMessage(uint64_t connectionId, std::string const & text);
  void OnClosed(uint64_t connectionId, std::string const & reason);

  Executor::TaskId Later(int64_t delayMs, std::function<void()> task);
  void Cancel(Executor::TaskId & id);

  Transport & m_transport;
  Executor & m_executor;
  crypto::Rng & m_rng;
  AllowFn m_isAllowed;
  PoolConfig m_config;
  std::shared_ptr<int> m_alive = std::make_shared<int>(0);

  uint64_t m_nextId = 1;
  std::map<uint64_t, std::unique_ptr<Connection>> m_connections;
  std::map<uint64_t, std::unique_ptr<Subscription>> m_subscriptions;
  std::map<uint64_t, std::unique_ptr<Publication>> m_publications;
  std::map<std::string, Health> m_health;
  std::vector<std::unique_ptr<Connection>> m_closed;  // destroyed outside their own callbacks
};
}  // namespace live_location::relay
