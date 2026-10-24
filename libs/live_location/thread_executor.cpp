#include "live_location/thread_executor.hpp"

#include <chrono>
#include <future>

namespace live_location
{
ThreadExecutor::~ThreadExecutor()
{
  Shutdown();
}

int64_t ThreadExecutor::NowMs() const
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void ThreadExecutor::Post(Task task)
{
  m_thread.Push(std::move(task));
}

Executor::TaskId ThreadExecutor::PostDelayed(int64_t delayMs, Task task)
{
  auto const result = m_thread.PushDelayed(std::chrono::milliseconds(std::max<int64_t>(0, delayMs)), std::move(task));
  return result.m_isSuccess ? result.m_id : kNoTask;
}

void ThreadExecutor::Cancel(TaskId id)
{
  if (id != kNoTask)
    m_thread.Cancel(id);
}

void ThreadExecutor::RunSync(Task const & task)
{
  std::promise<void> done;
  auto finished = done.get_future();
  Task run = [&task, &done]
  {
    task();
    done.set_value();
  };
  if (m_thread.Push(std::move(run)).m_isSuccess)
    finished.wait();
}

void ThreadExecutor::Shutdown()
{
  if (!m_thread.IsShutDown())
    m_thread.ShutdownAndJoin();
}
}  // namespace live_location
