#include "testing/testing.hpp"

#include "map/framework.hpp"
#include "map/live_location_marks.hpp"

#include "drape_frontend/visual_params.hpp"

#include "geometry/mercator.hpp"

#include <string>
#include <vector>

// Live location (NLL): a tap on a contact's dot (docs/LIVE_LOCATION.md §11.4).
namespace live_location_marks_tests
{
double constexpr kLat = 52.52;
double constexpr kLon = 13.405;

live_location::PositionInfo Bob()
{
  live_location::PositionInfo position;
  position.m_contactId = "c1";
  position.m_name = "Bob";
  position.m_location.m_lat = kLat;
  position.m_location.m_lon = kLon;
  position.m_location.m_acc = 10;
  return position;
}

UNIT_TEST(LiveLocationMarks_TapOnADot)
{
  df::VisualParams::Init(1.0, 1024);
  Framework frm(FrameworkParams(false /* m_enableDiffs */));
  LiveLocationMarks marks(frm.GetBookmarkManager());
  marks.Show({Bob()});
  auto const & ids = frm.GetBookmarkManager().GetUserMarkIds(UserMark::Type::LIVE_LOCATION);
  TEST_EQUAL(ids.size(), 1, ());

  // As drape reports a tap on the dot's label.
  place_page::BuildInfo onLabel;
  onLabel.m_source = place_page::BuildInfo::Source::User;
  onLabel.m_mercator = mercator::FromLatLon(kLat, kLon);
  onLabel.m_userMarkId = *ids.begin();

  // Without a listener (the desktop app), a plain place page with the contact's name. This aborted.
  frm.BuildAndSetPlacePageInfo(onLabel);
  TEST(frm.HasPlacePageInfo(), ());
  TEST_EQUAL(frm.GetCurrentPlacePageInfo().GetTitle(), "Bob", ());
  frm.DeactivateMapSelection();
  TEST(!frm.HasPlacePageInfo(), ());

  // With one (Android), the contact's id, and no place page.
  std::vector<std::string> tapped;
  frm.SetLiveLocationTapListener([&tapped](std::string const & contactId) { tapped.push_back(contactId); });
  frm.BuildAndSetPlacePageInfo(onLabel);
  TEST_EQUAL(tapped, (std::vector<std::string>{"c1"}), ());
  TEST(!frm.HasPlacePageInfo(), ());

  // A tap on the dot itself, which has no overlay of its own, finds it by position.
  place_page::BuildInfo onDot;
  onDot.m_mercator = onLabel.m_mercator;
  frm.BuildAndSetPlacePageInfo(onDot);
  TEST_EQUAL(tapped, (std::vector<std::string>{"c1", "c1"}), ());

  // Elsewhere, the usual place page.
  place_page::BuildInfo elsewhere;
  elsewhere.m_mercator = mercator::FromLatLon(kLat + 0.01, kLon);
  frm.BuildAndSetPlacePageInfo(elsewhere);
  TEST_EQUAL(tapped.size(), 2, ());
  TEST(frm.HasPlacePageInfo(), ());

  marks.Clear();
}
}  // namespace live_location_marks_tests
