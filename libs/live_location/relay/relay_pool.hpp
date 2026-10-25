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
  int64_t m_eoseTimeoutMs = 15'000;     // no EOSE for a REQ sent in this time: the connection is no use either
  int64_t m_connectTimeoutMs = 15'000;  // not open in this time: the connection failed
  int64_t m_lingerMs = 60'000;          // a connection used only to publish closes after this long without traffic
  int64_t m_backoffMinMs = 1'000;       // a failing relay is retried after this, doubling up to the maximum
  int64_t m_backoffMaxMs = 300'000;
  int64_t m_closedRetryMs = 30'000;  // a subscription the relay CLOSED is sent again after this
  size_t m_dedupe = 4096;            // event ids remembered per subscription
  size_t m_maxInvalidEvents = 32;    // events a connection may send that its REQ did not ask for or that fail
                                     // verification; one more, and the relay counts as failing
  int64_t m_echoTimeoutMs = 15'000;  // an accepted event that a REQ of its own connection asks for comes back
                                     // within this, or the relay does not deliver what it accepts ...
  int64_t m_deafBackoffMinMs = 300'000;  // ... and it is not listened on for this long, doubling up to the maximum
  int64_t m_deafBackoffMaxMs = 1'800'000;
};

enum class Placement
{
  All,             // on every relay of the list that is not failing
  FirstReachable,  // on the first relay of the list that is not failing: a listening relay (design doc D17).
                   // A relay found not to deliver what it accepts is skipped while another one can be used,
                   // and once its back-off is over, tried again next to it.
};

/// All relay traffic, on the executor's thread. A relay that fails (it cannot be reached, drops the
/// connection, or does not answer a publish within m_okTimeoutMs or a REQ with its EOSE within
/// m_eoseTimeoutMs) is skipped while it backs off. Subscriptions move to other relays meanwhile and come
/// back. The back-off doubles with each failure until the relay has answered a publish or a REQ, so that
/// one that drops every connection as it opens is not tried again every second; after one it left
/// unanswered, until it has answered one of that kind. Such an answer also ends the back-off at once.
/// Connections open when something needs them and close when nothing does: a connection without
/// subscriptions closes after m_lingerMs without traffic. Nothing connects to a relay that `isAllowed`
/// refuses (relay consent, spec §11).
///
/// The echo check: when a REQ of a FirstReachable subscription asks for the events that its own
/// connection publishes, every event the relay accepts must come back over it, and is delivered like any
/// other. One that has not within m_echoTimeoutMs of its OK shows that the relay accepts events without
/// delivering them: it is then "deaf" (m_deafBackoff*), and the subscription moves to the next relay.
/// When the back-off is over, the subscription runs on both until an event published comes back over the
/// deaf relay or does not. Publishing to it goes on throughout. A relay that has never sent such an event
/// back is not judged at all: some relays might never do so. Which relays have is the app's to remember
/// across runs (SetEchoing(), OnEchoed()): a relay already deaf when the app starts would otherwise never
/// be judged. Only an event published for the first time is judged: a relay does not deliver one it
/// already has, whatever its OK says. So an event that a listening REQ asks for must not be sent again.
class RelayPool
{
public:
  using SubscriptionId = uint64_t;
  using FiltersFn = std::function<std::vector<nostr::Filter>()>;
  using EventFn = std::function<void(nostr::Event const & event)>;
  using EoseFn = std::function<void(std::string const & url)>;
  using DoneFn = std::function<void(bool delivered)>;
  using AllowFn = std::function<bool(std::string const & url)>;
  using EchoFn = std::function<void(std::string const & url)>;
  using ConnectedFn = std::function<void(std::string const & url)>;

  RelayPool(Transport & transport, Executor & executor, crypto::Rng & rng, AllowFn isAllowed, PoolConfig config = {});
  ~RelayPool();

  RelayPool(RelayPool const &) = delete;
  RelayPool & operator=(RelayPool const &) = delete;

  /// A subscription on `urls`. `filters` is called whenever the REQ is (re)sent. Events arrive once,
  /// whichever relays deliver them, and only if they match the filters their relay was sent and their
  /// id and signature are valid: a copy that fails cannot keep an intact one from arriving through
  /// another relay. `onEose` runs once per relay and REQ.
  SubscriptionId Subscribe(Scope scope, Relays urls, Placement placement, FiltersFn filters, EventFn onEvent,
                           EoseFn onEose = {});
  /// Sends the REQs again with the current filters.
  void Refresh(SubscriptionId id);
  void Unsubscribe(SubscriptionId id);

  /// Sends `event` to every relay of `urls` that is not failing. `done(true)` follows the first OK that
  /// accepts it, `done(false)` the last refusal, failure or timeout when none accepted it. An event still
  /// waiting for its OK over a connection is not sent there again: this publication waits for that OK.
  void Publish(Scope const & scope, Relays const & urls, nostr::Event const & event, DoneFn done = {});

  /// Closes every connection and forgets every subscription and publication, without callbacks.
  void CloseAll();
  /// Whether a publication still waits for its relays' answers.
  bool HasPendingPublications() const { return !m_publications.empty(); }

  /// Whether `url` is backing off after a failure.
  bool IsFailing(std::string const & url) const;
  /// Whether `url` accepted an event without delivering it, and is backing off for it (the echo check).
  bool IsDeaf(std::string const & url) const;
  /// Relays known to send an event back to the connection that published it, e.g. on an earlier run.
  void SetEchoing(std::set<std::string> urls) { m_echoing.insert(urls.begin(), urls.end()); }
  /// Called on every event that comes back to the connection that published it.
  void OnEchoed(EchoFn fn) { m_onEchoed = std::move(fn); }
  /// Called whenever a connection opens: the relay can be reached, e.g. once the network is back.
  void OnConnected(ConnectedFn fn) { m_onConnected = std::move(fn); }
  /// The relay a FirstReachable subscription on `urls` relies on: the first that is allowed, not failing,
  /// and not found deaf, else the first that is not failing.
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

  /// What a relay did not answer, when that is why it failed.
  enum class Unanswered
  {
    Nothing,
    Publish,
    Req,
  };
  struct Health
  {
    int m_failures = 0;
    int64_t m_retryAtMs = 0;
    // Answers it owes: one that answers publishes and never a REQ, or the reverse, keeps backing off.
    bool m_owesOk = false;
    bool m_owesEose = false;
  };
  /// Unlike a failure, not forgotten when the relay answers again: it answers fine.
  struct Deafness
  {
    int m_misses = 0;
    int64_t m_retryAtMs = 0;
  };

  Connection & GetConnection(std::string const & url, Scope const & scope);
  Connection * FindConnection(uint64_t id);
  void Send(Connection & connection, std::string text);
  void Place(SubscriptionId id);
  void PlaceAllUsing(std::string const & url);
  void ArmEose(Connection & connection, std::string const & reqId);
  void Detach(Subscription & subscription, std::string const & url);
  void Fail(uint64_t connectionId, std::string const & reason, Unanswered unanswered = Unanswered::Nothing);
  void Answered(std::string const & url, Unanswered kind);
  void Drop(uint64_t connectionId);
  void Touch(Connection & connection);
  void Linger(Connection & connection);
  void OnPublishResult(uint64_t publicationId, std::string const & url, bool accepted);
  void OnEvent(Connection & connection, std::string const & reqId, nostr::Event const & event);
  void OnEcho(Connection & connection, std::string const & eventId);
  void ForgetEchoes(Connection & connection);
  void OnEchoMissing(uint64_t connectionId, std::string const & eventId);

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
  std::map<std::string, Deafness> m_deaf;
  std::set<std::string> m_echoing;  // relays that have sent an event back to the connection that published it
  EchoFn m_onEchoed;
  ConnectedFn m_onConnected;
  std::vector<std::unique_ptr<Connection>> m_closed;  // destroyed outside their own callbacks
};
}  // namespace live_location::relay
