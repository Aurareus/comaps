#pragma once

// Live location (NLL): contacts' positions as dots on the map (docs/LIVE_LOCATION.md §8.1, §11.4).

#include "map/user_mark.hpp"

#include "live_location/manager/marks.hpp"

#include <string>
#include <vector>

class BookmarkManager;

/// A contact's dot: a coloured circle, grey once its position is old, with the contact's name.
class LiveLocationMark : public UserMark
{
public:
  explicit LiveLocationMark(m2::PointD const & ptOrg);

  void Set(live_location::MarkSpec const & mark);
  std::string const & GetContactId() const { return m_contactId; }

  drape_ptr<SymbolNameZoomInfo> GetSymbolNames() const override { return nullptr; }
  drape_ptr<ColoredSymbolZoomInfo> GetColoredSymbols() const override;
  drape_ptr<TitlesInfo> GetTitleDecl() const override;
  bool IsAvailableForSearch() const override { return false; }

private:
  ColoredSymbolZoomInfo m_symbol;
  dp::TitleDecl m_title;
  std::string m_contactId;
};

/// Shows the manager's positions on the map. Call on the GUI thread.
class LiveLocationMarks
{
public:
  explicit LiveLocationMarks(BookmarkManager & bookmarks) : m_bookmarks(bookmarks) {}

  void Show(std::vector<live_location::PositionInfo> const & positions);
  void Clear();

private:
  BookmarkManager & m_bookmarks;
  live_location::MarksSync m_sync;
};
