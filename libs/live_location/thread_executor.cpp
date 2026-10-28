#include "live_location/thread_executor.hpp"

#include "base/logging.hpp"

#include <chrono>
#include <exception>
#include <future>

namespace live_location
{
namespace
{
// A task that throws would end the thread, and the app with it (std::terminate). It is logged instead, as an
// error that stops debug builds, and the next task runs. Whatever the task did before it threw stays done.
void RunGuarded(Executor::Task const & task)
{
  try
  {
    task();
  }
  catch (std::exception const & e)
  {
    LOG(LERROR, ("Live location: a task failed:", e.what()));
  }
  catch (...)
  {
    LOG(LERROR, ("Live location: a task failed"));
  }
}
}  // namespace

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
  m_thread.Push([task = std::move(task)] { RunGuarded(task); });
}

Executor::TaskId ThreadExecutor::PostDelayed(int64_t delayMs, Task task)
{
  auto const result = m_thread.PushDelayed(std::chrono::milliseconds(std::max<int64_t>(0, delayMs)),
                                           [task = std::move(task)] { RunGuarded(task); });
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
  // What the task throws goes back to the caller, as a call's error: defaults returned in its place could
  // mislead (for the app's start, false reads as a store that cannot be read).
  Task run = [&task, &done]
  {
    try
    {
      task();
      done.set_value();
    }
    catch (...)
    {
      done.set_exception(std::current_exception());
    }
  };
  if (m_thread.Push(std::move(run)).m_isSuccess)
    finished.get();
}

void ThreadExecutor::Shutdown()
{
  if (!m_thread.IsShutDown())
    m_thread.ShutdownAndJoin();
}
}  // namespace live_location
