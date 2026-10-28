#pragma once

#include "live_location/executor.hpp"

#include "base/thread_pool_delayed.hpp"

// The production executor: one thread of its own, the system clock for time, a monotonic clock for
// delays (design doc §8.2). A posted task that throws is logged, an error that stops debug builds, and does
// not stop the thread; one run by RunSync() throws in its caller.
namespace live_location
{
class ThreadExecutor : public Executor
{
public:
  ThreadExecutor() = default;
  /// Stops the thread; tasks not run yet are dropped.
  ~ThreadExecutor() override;

  int64_t NowMs() const override;
  void Post(Task task) override;
  TaskId PostDelayed(int64_t delayMs, Task task) override;
  void Cancel(TaskId id) override;

  /// Runs `task` on the thread and waits for it; what it throws is thrown here. Never from the thread itself.
  void RunSync(Task const & task);
  void Shutdown();

private:
  base::DelayedThreadPool m_thread{1, base::DelayedThreadPool::Exit::SkipPending};
};
}  // namespace live_location
