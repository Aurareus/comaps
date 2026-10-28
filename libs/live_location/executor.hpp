#pragma once

#include <cstdint>
#include <functional>

namespace live_location
{
/// The thread that owns the live location state, with its clock and timers. Everything in the relay pool
/// and the manager runs on it. Production code wraps a base::DelayedThreadPool with the system clock;
/// tests use virtual time.
class Executor
{
public:
  using Task = std::function<void()>;
  using TaskId = uint64_t;
  static TaskId constexpr kNoTask = 0;

  virtual ~Executor() = default;

  /// Wall-clock time in milliseconds since the Unix epoch. The protocol works in seconds of it.
  virtual int64_t NowMs() const = 0;
  /// Runs `task` on the thread, after the tasks already posted. Thread-safe.
  virtual void Post(Task task) = 0;
  /// Runs `task` on the thread after at least `delayMs`. Call on the thread.
  virtual TaskId PostDelayed(int64_t delayMs, Task task) = 0;
  /// A delayed task that has not run yet does not run. Call on the thread.
  virtual void Cancel(TaskId id) = 0;

  int64_t Now() const { return NowMs() / 1000; }
};
}  // namespace live_location
