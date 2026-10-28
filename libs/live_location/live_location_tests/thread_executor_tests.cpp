#include "testing/testing.hpp"

#include "live_location/live_location_tests/scenario.hpp"

#include "live_location/thread_executor.hpp"

#include "base/logging.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <thread>
#include <vector>

// The production executor: order, delays, cancellation, RunSync.
namespace thread_executor_tests
{
using namespace live_location;

UNIT_TEST(ThreadExecutor_RunsInOrderAndCancels)
{
  ThreadExecutor executor;
  std::vector<int> order;  // touched on the executor's thread only, read through RunSync
  std::atomic<bool> cancelledRan = false;
  executor.Post([&] { order.push_back(1); });
  executor.Post([&] { order.push_back(2); });
  auto const later = executor.PostDelayed(30, [&] { order.push_back(4); });
  auto const cancelled = executor.PostDelayed(20, [&] { cancelledRan = true; });
  executor.PostDelayed(10, [&] { order.push_back(3); });
  executor.RunSync([&] { executor.Cancel(cancelled); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  std::vector<int> seen;
  executor.RunSync([&] { seen = order; });
  TEST_EQUAL(seen, std::vector<int>({1, 2, 3, 4}), ());
  TEST(!cancelledRan, ("a cancelled task does not run"));
  TEST_NOT_EQUAL(later, Executor::kNoTask, ());

  int64_t const now = executor.NowMs();
  int64_t const system =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count();
  TEST_LESS(std::abs(now - system), 1000, ("wall-clock time"));
  executor.Shutdown();
  executor.Post([&] { order.push_back(5); });  // dropped after shutdown
}

// A task that throws does not end the thread, which would end the app: later tasks run, and RunSync returns.
UNIT_TEST(ThreadExecutor_ATaskThatThrowsStopsNothing)
{
  base::ScopedLogAbortLevelChanger const logOnly(LCRITICAL);  // debug builds stop at the error otherwise
  ThreadExecutor executor;
  std::atomic<int> ran = 0;
  executor.Post([] { throw std::runtime_error("posted"); });
  executor.Post([] { throw 42; });  // not a std::exception
  executor.PostDelayed(5, [] { throw std::logic_error("delayed"); });
  executor.PostDelayed(10, [&] { ++ran; });
  // A call waiting for its task gets what it threw.
  TEST(live_location_tests::Throws<std::bad_alloc>([&] { executor.RunSync([] { throw std::bad_alloc(); }); }), ());
  TEST(live_location_tests::Throws<int>([&] { executor.RunSync([] { throw 42; }); }), ());
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  executor.RunSync([&] { ++ran; });
  TEST_EQUAL(ran.load(), 2, ());
}
}  // namespace thread_executor_tests
