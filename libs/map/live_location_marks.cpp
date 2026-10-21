#include "map/live_location_marks.hpp"

#include "map/bookmark_manager.hpp"

#include "drape_frontend/visual_params.hpp"

#include "geometry/mercator.hpp"

namespace
{
float constexpr kRadius = 10.0f;  // in dp, the outline included: 20 dp across
float constexpr kOutline = 2.0f;
float constexpr kTextSize = 12.0f;
dp::Color constexpr kText(0x21, 0x21, 0x21);

/// The marks' changes within one edit session.
class SessionSink : public live_location::MarkSink
{
public:
  explicit SessionSink(BookmarkManager::EditSession & session) : m_session(session) {}

  Handle Create(live_location::MarkSpec const & mark) override
  {
    auto * created = m_session.CreateUserMark<LiveLocationMark>(mercator::FromLatLon(mark.m_lat, mark.m_lon));
    created->Set(mark);
    return created->GetId();
  }

  void Update(Handle handle, live_location::MarkSpec const & mark) override
  {
    if (auto * existing = m_session.GetMarkForEdit<LiveLocationMark>(handle))
      existing->Set(mark);
  }

  void Remove(Handle handle) override { m_session.DeleteUserMark(handle); }

private:
  BookmarkManager::EditSession & m_session;
};
}  // namespace

LiveLocationMark::LiveLocationMark(m2::PointD const & ptOrg) : UserMark(ptOrg, UserMark::Type::LIVE_LOCATION)
{
  auto const vs = static_cast<float>(df::VisualParams::Instance().GetVisualScale());
  df::ColoredSymbolViewParams params;
  params.m_color = dp::Color(live_location::kStaleColor);
  params.m_outlineColor = dp::Color::White();
  params.m_outlineWidth = kOutline * vs;
  params.m_radiusInPixels = kRadius * vs;
  m_symbol.m_needOverlay = false;  // a contact's dot never gives way to map labels
  m_symbol.m_zoomInfo.emplace(1, params);

  m_title.m_anchor = dp::Top;
  m_title.m_primaryTextFont = dp::FontDecl(kText, kTextSize, dp::Color::White());
  m_title.m_primaryOffset = m2::PointF(0.0f, 1.0f);  // below the dot, whose size drape adds
  m_title.m_primaryOptional = true;
}

void LiveLocationMark::Set(live_location::MarkSpec const & mark)
{
  m_ptOrg = mercator::FromLatLon(mark.m_lat, mark.m_lon);
  m_symbol.m_zoomInfo.begin()->second.m_color = dp::Color(mark.m_rgba);
  m_title.m_primaryText = mark.m_label;
  m_contactId = mark.m_contactId;
  SetDirty();
}

drape_ptr<df::UserPointMark::ColoredSymbolZoomInfo> LiveLocationMark::GetColoredSymbols() const
{
  return make_unique_dp<ColoredSymbolZoomInfo>(m_symbol);
}

drape_ptr<df::UserPointMark::TitlesInfo> LiveLocationMark::GetTitleDecl() const
{
  auto titles = make_unique_dp<TitlesInfo>();
  titles->push_back(m_title);
  return titles;
}

void LiveLocationMarks::Show(std::vector<live_location::PositionInfo> const & positions)
{
  auto session = m_bookmarks.GetEditSession();
  SessionSink sink(session);
  m_sync.Apply(live_location::MarksFor(positions), sink);
}

void LiveLocationMarks::Clear()
{
  auto session = m_bookmarks.GetEditSession();
  SessionSink sink(session);
  m_sync.Clear(sink);
}
