package app.organicmaps.livelocation;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import app.organicmaps.MwmApplication;
import app.organicmaps.R;
import app.organicmaps.sdk.Framework;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.util.UiUtils;
import app.organicmaps.widget.placepage.PlacePageViewModel;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import java.util.List;
import java.util.Objects;

/**
 * Live location (NLL): the sheet a tap on a contact's dot opens over the map (docs/LIVE_LOCATION.md §11.4):
 * name, status, last update, accuracy and a low battery, "Center", and the contact's details. It is handled
 * as the place page is: the map stays bright and usable around it, the map buttons rise above it, "Center"
 * puts the contact in the part of the map above it, a drag down closes it, and so does whatever closes the
 * place page; a place opened on the map takes its place, and it survives the map screen's recreation. Built
 * once per contact; positions arriving every few seconds update its lines in place.
 */
final class ContactSheet implements LiveLocation.Listener
{
  private static final int CENTER_ZOOM = 16;

  /** Whose sheet is open, kept across the map screen's recreation as the place page's object is. */
  static final class Model extends ViewModel
  {
    @Nullable
    String mContactId;
  }

  @NonNull
  private final AppCompatActivity mActivity;
  @NonNull
  private final CoordinatorLayout mParent;
  @NonNull
  private final Model mModel;
  // The place page's: what the map buttons follow, and the place opened.
  @NonNull
  private final PlacePageViewModel mPlacePage;
  private final int mViewportMinHeight;
  @Nullable
  private View mSheet;
  @Nullable
  private BottomSheetBehavior<View> mBehavior;
  private boolean mListening;
  // Whether the sheet moves the map buttons and sets the map's visible part: not once a place page replaces it.
  private boolean mMovesButtons;
  // What the map buttons were told last: the sheet's width, and its top while it rests open.
  private int mToldWidth;
  private int mToldTop;
  // After each layout pass: the sheet where the behaviour put it. A layout listener sees it earlier, at the
  // top of the map, before the behaviour moves it down; told so, the map buttons would hide.
  private final ViewTreeObserver.OnGlobalLayoutListener mLaidOut = this::onLaidOut;
  // The lines updated in place.
  @Nullable
  private View mHeader;
  @Nullable
  private TextView mLastSeen;
  @Nullable
  private TextView mAccuracy;
  @Nullable
  private TextView mBattery;
  @Nullable
  private View mCenter;

  ContactSheet(@NonNull AppCompatActivity activity)
  {
    mActivity = activity;
    mParent = activity.findViewById(R.id.coordinator);
    mModel = new ViewModelProvider(activity, new ViewModelProvider.Factory() {
               @NonNull
               @Override
               public <T extends ViewModel> T create(@NonNull Class<T> modelClass)
               {
                 return modelClass.cast(new Model());
               }
             }).get(Model.class);
    mPlacePage = new ViewModelProvider(activity).get(PlacePageViewModel.class);
    mViewportMinHeight = activity.getResources().getDimensionPixelSize(R.dimen.viewport_min_height);
    mPlacePage.getMapObject().observe(activity, object -> {
      if (object != null)
        close(false);
    });
    // While the sheet is up, the buttons stay above it, whatever a place page closing under it reports.
    mPlacePage.getPlacePageDistanceToTop().observe(activity, top -> {
      if (mSheet != null && mMovesButtons && isUp() && top != null && top > mSheet.getTop())
        mPlacePage.setPlacePageDistanceToTop(mSheet.getTop());
    });
  }

  /** Shows `contactId`'s sheet, in the place of a place page or of another contact's sheet. */
  void open(@NonNull String contactId)
  {
    if (mPlacePage.getMapObject().getValue() != null)
      mPlacePage.setMapObject(null);
    mModel.mContactId = contactId;
    mMovesButtons = true;
    final boolean created = mSheet == null;
    if (created)
      create();
    listen(true);
    build(contactId);
    if (mSheet == null || mModel.mContactId == null)
      return; // Closed already: the contact has gone.
    if (created)
      mSheet.post(() -> {
        if (mBehavior != null)
          mBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);
      });
    else if (mBehavior != null)
      mBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);
  }

  /** False if it was not open. `lowerButtons`: nothing takes its place, so the map buttons go back down. */
  boolean close(boolean lowerButtons)
  {
    mModel.mContactId = null;
    if (mBehavior == null)
      return false;
    mMovesButtons &= lowerButtons;
    if (mBehavior.getState() == BottomSheetBehavior.STATE_HIDDEN)
      remove(); // Not shown yet.
    else
      mBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
    return true;
  }

  void onStart()
  {
    if (mSheet == null)
    {
      // The map screen was recreated with the sheet open.
      if (mModel.mContactId != null)
        open(mModel.mContactId);
      return;
    }
    listen(true);
    refresh();
  }

  void onStop()
  {
    listen(false);
  }

  @Override
  public void onContacts(@NonNull List<Contact> contacts)
  {
    refresh();
  }

  @Override
  public void onPositions(@NonNull List<Position> positions)
  {
    refresh();
  }

  private void create()
  {
    // The style gives it the place page's width. The navigation bar's room comes before its first layout,
    // so that it opens to where it rests: the behaviour would give it only after that layout. Read here once
    // the map screen is shown; until then, as after its recreation, the window gives it to every view first.
    final View sheet = LayoutInflater.from(mActivity).inflate(R.layout.live_location_contact_sheet, mParent, false);
    final WindowInsetsCompat insets = ViewCompat.getRootWindowInsets(mParent);
    if (insets != null)
      fitBars(sheet, insets);
    ViewCompat.setOnApplyWindowInsetsListener(sheet, (v, windowInsets) -> {
      fitBars(v, windowInsets);
      return windowInsets;
    });
    mSheet = sheet;
    mToldWidth = 0;
    mToldTop = -1;
    mParent.addView(sheet);
    sheet.getViewTreeObserver().addOnGlobalLayoutListener(mLaidOut);
    final BottomSheetBehavior<View> behavior = BottomSheetBehavior.from(sheet);
    mBehavior = behavior;
    behavior.setHideable(true);
    behavior.setSkipCollapsed(true);
    behavior.setFitToContents(true);
    behavior.setState(BottomSheetBehavior.STATE_HIDDEN);
    behavior.addBottomSheetCallback(new BottomSheetBehavior.BottomSheetCallback() {
      @Override
      public void onStateChanged(@NonNull View bottomSheet, int newState)
      {
        if (bottomSheet != mSheet)
          return;
        if (newState == BottomSheetBehavior.STATE_HIDDEN)
        {
          remove();
        }
        else if (newState == BottomSheetBehavior.STATE_EXPANDED)
        {
          // Its height changed while it moved, e.g. a first position added its lines: the behaviour puts it
          // where it rests at its next layout.
          if (bottomSheet.getTop() != Math.max(0, mParent.getHeight() - bottomSheet.getHeight()))
            bottomSheet.requestLayout();
          onLaidOut();
        }
      }

      @Override
      public void onSlide(@NonNull View bottomSheet, float slideOffset)
      {
        if (bottomSheet == mSheet && mMovesButtons && isUp())
          mPlacePage.setPlacePageDistanceToTop(bottomSheet.getTop());
      }
    });
  }

  /** The navigation bar's room below the sheet's content, and the side bars' beside it, as for the place page. */
  private static void fitBars(@NonNull View sheet, @NonNull WindowInsetsCompat windowInsets)
  {
    final Insets bars = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars());
    sheet.setPadding(sheet.getPaddingLeft(), sheet.getPaddingTop(), sheet.getPaddingRight(), bars.bottom);
    final ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) sheet.getLayoutParams();
    if (params.leftMargin == bars.left && params.rightMargin == bars.right)
      return;
    params.leftMargin = bars.left;
    params.rightMargin = bars.right;
    sheet.setLayoutParams(params);
  }

  /**
   * After a layout pass, and once it rests open: which map buttons are behind it (as by the place page's
   * width), where they go above it, and the map's visible part. It moves between, while opening, closing or
   * dragged: onSlide tells that.
   */
  private void onLaidOut()
  {
    if (mSheet == null || mBehavior == null || !mMovesButtons)
      return;
    if (mSheet.getWidth() != mToldWidth)
    {
      mToldWidth = mSheet.getWidth();
      mPlacePage.setPlacePageWidth(mToldWidth);
    }
    if (mBehavior.getState() != BottomSheetBehavior.STATE_EXPANDED || mSheet.getTop() == mToldTop)
      return;
    mToldTop = mSheet.getTop();
    mPlacePage.setPlacePageDistanceToTop(mToldTop);
    setVisibleMap(mToldTop);
  }

  private boolean isUp()
  {
    return mBehavior != null && mBehavior.getState() != BottomSheetBehavior.STATE_HIDDEN;
  }

  private void remove()
  {
    listen(false);
    if (mSheet != null)
    {
      mSheet.getViewTreeObserver().removeOnGlobalLayoutListener(mLaidOut);
      mParent.removeView(mSheet);
    }
    mSheet = null;
    mBehavior = null;
    mHeader = null;
    mLastSeen = null;
    mAccuracy = null;
    mBattery = null;
    mCenter = null;
    // Before the map screen's first layout, nothing has moved.
    if (mMovesButtons && mParent.getHeight() > 0)
    {
      mPlacePage.setPlacePageDistanceToTop(mParent.getHeight());
      setVisibleMap(mParent.getHeight());
    }
    mMovesButtons = false;
  }

  /** The part of the map above the sheet, which centering uses, as the place page sets it. */
  private void setVisibleMap(int bottom)
  {
    // Android Auto sets it for its own screen.
    if (bottom < mViewportMinHeight || MwmApplication.from(mActivity).getDisplayManager().isCarDisplayUsed())
      return;
    Framework.nativeSetVisibleRect(0, 0, mParent.getWidth(), bottom);
  }

  private void listen(boolean listen)
  {
    if (listen == mListening)
      return;
    mListening = listen;
    if (listen)
      LiveLocation.addListener(this);
    else
      LiveLocation.removeListener(this);
  }

  private void build(@NonNull String id)
  {
    final Context context = mActivity;
    final LiveLocationViews views = new LiveLocationViews(
        LayoutInflater.from(context), Objects.requireNonNull(mSheet).findViewById(R.id.live_location_content));
    views.clear();
    mHeader = views.row("", null, null, null);
    mLastSeen = views.text("");
    mAccuracy = views.text("");
    mBattery = views.text(context.getString(R.string.live_location_battery_low));
    mCenter = views.button(context.getString(R.string.live_location_center), v -> {
      final Position position = positionOf(id);
      if (position == null || mSheet == null)
        return;
      setVisibleMap(mSheet.getTop());
      Framework.nativeZoomToPoint(position.lat, position.lon, CENTER_ZOOM, true);
    });
    views.outlinedButton(context.getString(R.string.live_location_contact_details),
                         v -> mActivity.startActivity(LiveLocationActivity.contactIntent(context, id)));
    refresh();
  }

  private void refresh()
  {
    final String id = mModel.mContactId;
    if (mSheet == null || id == null || mHeader == null || mLastSeen == null || mAccuracy == null || mBattery == null
        || mCenter == null)
      return;
    final Contact contact = LiveLocation.getContact(id);
    if (contact == null || contact.hidden)
    {
      // Deleted, hidden, or the feature turned off meanwhile.
      close(true);
      return;
    }
    LiveLocationViews.setRow(mHeader, contact.name, LiveLocationText.status(mActivity, contact),
                             LiveLocationText.badge(mActivity, contact));
    final Position position = positionOf(contact.id);
    UiUtils.showIf(position != null, mLastSeen, mAccuracy, mCenter);
    UiUtils.showIf(position != null && position.low, mBattery);
    if (position == null)
      return;
    mLastSeen.setText(mActivity.getString(R.string.live_location_last_seen, LiveLocationText.ago(position.timeMs)));
    mAccuracy.setText(mActivity.getString(R.string.live_location_accuracy, Math.round(position.accuracy)));
  }

  @Nullable
  private static Position positionOf(@NonNull String contactId)
  {
    for (Position position : LiveLocation.getPositions())
      if (position.contactId.equals(contactId))
        return position;
    return null;
  }
}
