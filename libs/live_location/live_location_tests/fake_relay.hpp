#pragma once

#include "live_location/executor.hpp"
#include "live_location/nostr/event.hpp"
#include "live_location/nostr/filter.hpp"
#include "live_location/relay/transport.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// Virtual time and in-process relays, for tests of the relay pool and the manager.
namespace live_location_tests
{
/// An executor on virtual time: tasks run only inside RunUntil(), in time order.
class VirtualExecutor : public live_location::Executor
{
public:
  explicit VirtualExecutor(int64_t startMs) : m_nowMs(startMs) {}

  int64_t NowMs() const override { return m_nowMs; }
  void Post(Task task) override;
  TaskId PostDelayed(int64_t delayMs, Task task) override;
  void Cancel(TaskId id) override;

  /// Runs the tasks due by `untilMs` in order, moving the clock to each, then to `untilMs`.
  void RunUntil(int64_t untilMs);
  void RunFor(int64_t ms) { RunUntil(m_nowMs + ms); }
  /// Runs what is due now, including what that posts for now.
  void RunPending() { RunUntil(m_nowMs); }
  size_t Pending() const { return m_queue.size(); }

private:
  using Key = std::pair<int64_t, uint64_t>;  // due time, order of posting
  int64_t m_nowMs;
  uint64_t m_order = 0;
  TaskId m_nextId = 1;
  std::map<Key, std::pair<TaskId, Task>> m_queue;
  std::map<TaskId, Key> m_index;
};

class FakeRelay;

/// Connects sockets to the FakeRelay registered for a URL; unknown URLs refuse.
class FakeTransport : public live_location::relay::Transport
{
public:
  explicit FakeTransport(VirtualExecutor & executor) : m_executor(executor) {}

  FakeRelay & Add(std::string const & url);
  FakeRelay * Find(std::string const & url);
  std::unique_ptr<live_location::relay::Socket> Connect(std::string const & url,
                                                        live_location::relay::SocketListener & listener) override;

  /// Connection attempts per URL so far.
  std::map<std::string, size_t> m_attempts;

private:
  VirtualExecutor & m_executor;
  std::map<std::string, std::unique_ptr<FakeRelay>> m_relays;
};

/// A NIP-01 relay: it verifies events, keeps the newest addressable event per (pubkey, kind, d), forwards
/// ephemeral ones without keeping them, honours NIP-40 expiration, and answers REQ with the stored
/// matches, EOSE, then live ones. Faults can be switched on.
class FakeRelay
{
public:
  struct Link;

  FakeRelay(VirtualExecutor & executor, std::string url) : m_executor(executor), m_url(std::move(url)) {}

  /// Refuses connections; going down also drops the open ones.
  void SetDown(bool down);
  /// Closes every connection, as a restart would.
  void DropConnections();
  /// Inserts an event as if someone published it: kept and forwarded (e.g. a replayed old event).
  void Inject(live_location::nostr::Event const & event);
  /// Ends every subscription with CLOSED, as a rate-limiting relay would.
  void CloseSubscriptions(std::string const & reason);

  int64_t m_latencyMs = 40;
  bool m_silent = false;     // accepts connections, then never answers: a dead connection
  bool m_duplicate = false;  // sends every event to subscribers twice
  bool m_refuse = false;     // answers every EVENT with OK false

  size_t OpenConnections() const;
  /// Every message received, per connection id, in order.
  std::map<uint64_t, std::vector<std::string>> m_received;
  std::vector<live_location::nostr::Event> Stored() const;
  std::string const & Url() const { return m_url; }

  // For FakeTransport.
  std::unique_ptr<live_location::relay::Socket> Accept(live_location::relay::SocketListener & listener);
  void Receive(std::shared_ptr<Link> const & link, std::string const & text);

private:
  void SendTo(std::shared_ptr<Link> const & link, std::string text);
  void Store(live_location::nostr::Event const & event);
  void Forward(live_location::nostr::Event const & event);
  bool Expired(live_location::nostr::Event const & event) const;

  VirtualExecutor & m_executor;
  std::string m_url;
  bool m_down = false;
  uint64_t m_nextLink = 1;
  std::vector<std::shared_ptr<Link>> m_links;
  std::vector<live_location::nostr::Event> m_events;
};

bool Matches(live_location::nostr::Filter const & filter, live_location::nostr::Event const & event);
}  // namespace live_location_tests
