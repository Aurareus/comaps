package app.organicmaps.livelocation;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import app.organicmaps.maplayer.MapButtonsViewModel;
import app.organicmaps.sdk.Framework;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;

/**
 * Live location (NLL): what the map screen shows of it (docs/LIVE_LOCATION.md §11.3, §11.4): while the
 * user shares, an indicator among the map buttons with the number of people, which opens "Manage
 * sharing"; the sheet of a contact's dot; the offer to resume a share after the process died; and
 * relay consent questions.
 */
public final class LiveLocationMapUi implements LiveLocation.Listener, LiveLocationFeature.Presenter
{
  @NonNull
  private final AppCompatActivity mActivity;
  @NonNull
  private final MapButtonsViewModel mMapButtons;
  @NonNull
  private final ContactSheet mContactSheet;
  @Nullable
  private AlertDialog mDialog;
  private boolean mStarted;

  public LiveLocationMapUi(@NonNull AppCompatActivity activity)
  {
    mActivity = activity;
    mMapButtons = new ViewModelProvider(activity).get(MapButtonsViewModel.class);
    mContactSheet = new ContactSheet(activity);
  }

  public void onStart()
  {
    if (!LiveLocationFeature.isEnabled(mActivity))
    {
      mContactSheet.close(true);
      updateIndicator();
      return;
    }
    mStarted = true;
    LiveLocation.addListener(this);
    LiveLocationFeature.attachPresenter(this);
    mContactSheet.onStart();
    updateIndicator();
    offerResume(LiveLocation.getSharing());
  }

  public void onStop()
  {
    if (!mStarted)
      return;
    mStarted = false;
    LiveLocation.removeListener(this);
    LiveLocationFeature.detachPresenter(this);
    mContactSheet.onStop();
    if (mDialog != null)
      mDialog.dismiss();
    mDialog = null;
  }

  @Override
  public void onSharing(@NonNull Sharing sharing)
  {
    updateIndicator();
    offerResume(sharing);
  }

  @Override
  public void onDotTapped(@NonNull String contactId)
  {
    mContactSheet.open(contactId);
  }

  /** Closes the sheet of a contact's dot, where the place page is closed. False if it was not open. */
  public boolean closeSheet()
  {
    return mContactSheet.close(true);
  }

  /**
   * Moves the map to a contact's position. Following the user's own position stops first, as it does for a
   * bookmark or a search result: the map would otherwise go back to it at the next fix.
   */
  static void showOnMap(@NonNull Position position, int zoom)
  {
    Framework.nativeStopLocationFollow();
    Framework.nativeZoomToPoint(position.lat, position.lon, zoom, true);
  }

  @Override
  public void presentConsent(@NonNull ConsentRequest request)
  {
    show(LiveLocationDialogs.showConsent(mActivity, request, consent -> LiveLocationFeature.onPresented()));
  }

  @Override
  public void presentMessage(@StringRes int message)
  {
    show(LiveLocationDialogs.showNotice(mActivity, message, LiveLocationFeature::onPresented));
  }

  private void offerResume(@NonNull Sharing sharing)
  {
    if (sharing.active || sharing.resumable.isEmpty() || mDialog != null)
      return;
    show(LiveLocationDialogs.showResume(mActivity, sharing, () -> {
      // Without the permissions, the share screen asks for them.
      if (LocationUtils.checkFineLocationPermission(mActivity) && LiveLocationService.canNotify(mActivity)
          && LiveLocation.startSharing(sharing.resumable))
        LiveLocationService.start(mActivity);
      else
        mActivity.startActivity(LiveLocationActivity.resumeIntent(mActivity));
    }));
  }

  private void show(@NonNull AlertDialog dialog)
  {
    if (mDialog != null)
      mDialog.dismiss();
    mDialog = dialog;
    dialog.setOnDismissListener(d -> {
      if (mDialog == d)
        mDialog = null;
    });
  }

  private void updateIndicator()
  {
    final Sharing sharing = LiveLocation.getSharing();
    mMapButtons.setLiveLocationSharing(mStarted && sharing.active ? sharing.recipients.size() : 0);
  }
}
