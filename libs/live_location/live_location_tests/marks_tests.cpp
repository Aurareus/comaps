#include "testing/testing.hpp"

#include "live_location/manager/marks.hpp"

#include <map>
#include <string>
#include <vector>

// The dots on the map, against a stub of the map's side.
namespace marks_tests
{
using namespace live_location;

class StubSink : public MarkSink
{
public:
  Handle Create(MarkSpec const & mark) override
  {
    m_log.push_back("create " + mark.m_label);
    m_marks[m_next] = mark;
    return m_next++;
  }
  void Update(Handle handle, MarkSpec const & mark) override
  {
    m_log.push_back("update " + mark.m_label);
    m_marks.at(handle) = mark;
  }
  void Remove(Handle handle) override
  {
    m_log.push_back("remove " + m_marks.at(handle).m_label);
    m_marks.erase(handle);
  }

  std::vector<std::string> m_log;
  std::map<Handle, MarkSpec> m_marks;

private:
  Handle m_next = 1;
};

PositionInfo At(std::string const & id, std::string const & name, double lat, bool stale = false)
{
  PositionInfo position;
  position.m_contactId = id;
  position.m_name = name;
  position.m_location.m_lat = lat;
  position.m_location.m_lon = 13.4;
  position.m_stale = stale;
  return position;
}

UNIT_TEST(Marks_FewestChanges)
{
  StubSink sink;
  MarksSync sync;
  sync.Apply(MarksFor({At("a1", "Bob", 52.0), At("c3", "Carol", 48.0)}), sink);
  TEST_EQUAL(sink.m_log, std::vector<std::string>({"create Bob", "create Carol"}), ());

  sink.m_log.clear();
  sync.Apply(MarksFor({At("a1", "Bob", 52.0), At("c3", "Carol", 48.1)}), sink);
  TEST_EQUAL(sink.m_log, std::vector<std::string>({"update Carol"}), ("only what moved changes"));

  sink.m_log.clear();
  sync.Apply(MarksFor({At("a1", "Bob", 52.0, true)}), sink);
  TEST_EQUAL(sink.m_log, std::vector<std::string>({"update Bob", "remove Carol"}), ());
  TEST_EQUAL(sink.m_marks.size(), 1, ());
  TEST_EQUAL(sink.m_marks.begin()->second.m_rgba, kStaleColor, ("an old position is grey"));

  sink.m_log.clear();
  sync.Apply(MarksFor({At("a1", "Bob", 52.0)}), sink);
  TEST(sink.m_log == std::vector<std::string>({"update Bob"}) && sink.m_marks.begin()->second.m_rgba == ColorOf("a1"),
       ("fresh again: its colour is back"));

  sync.Clear(sink);
  TEST(sink.m_marks.empty(), ());
}

UNIT_TEST(Marks_ColoursAreStablePerContact)
{
  TEST_EQUAL(ColorOf("a1"), ColorOf("a1"), ());
  TEST_NOT_EQUAL(ColorOf("a1"), kStaleColor, ());
  std::map<uint32_t, int> used;
  for (int i = 0; i < 64; ++i)
    ++used[ColorOf("contact " + std::to_string(i))];
  TEST_GREATER(used.size(), 4, ("contacts get different colours"));
}
}  // namespace marks_tests
