package app.organicmaps.livelocation;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import app.organicmaps.R;
import app.organicmaps.maplayer.MapButtonsViewModel;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;

/**
 * Live location (NLL): what the map screen shows of it (docs/LIVE_LOCATION.md §11.3, §11.4): while the
 * user shares, an indicator among the map buttons with the number of people, which opens "Manage
 * sharing"; the sheet of a contact's dot; the offer to resume a share after the process died; and
 * relay consent questions.
 */
public final class LiveLocationMapUi implements LiveLocation.Listener, LiveLocationFeature.ConsentPresenter
{
  @NonNull
  private final AppCompatActivity mActivity;
  @NonNull
  private final MapButtonsViewModel mMapButtons;
  @Nullable
  private AlertDialog mDialog;
  private boolean mStarted;

  public LiveLocationMapUi(@NonNull AppCompatActivity activity)
  {
    mActivity = activity;
    mMapButtons = new ViewModelProvider(activity).get(MapButtonsViewModel.class);
  }

  public void onStart()
  {
    if (!LiveLocationFeature.isEnabled(mActivity))
    {
      updateIndicator();
      return;
    }
    mStarted = true;
    LiveLocation.addListener(this);
    LiveLocationFeature.attachConsentPresenter(this);
    updateIndicator();
    if (LiveLocationFeature.takeStoppedUnseen())
      show(
          LiveLocationDialogs.showMessage(mActivity, null, mActivity.getString(R.string.live_location_stopped_unseen)));
    else
      offerResume(LiveLocation.getSharing());
  }

  public void onStop()
  {
    if (!mStarted)
      return;
    mStarted = false;
    LiveLocation.removeListener(this);
    LiveLocationFeature.detachConsentPresenter(this);
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
    ContactSheet.open(mActivity.getSupportFragmentManager(), contactId);
  }

  @Override
  public void presentConsent(@NonNull ConsentRequest request)
  {
    show(LiveLocationDialogs.showConsent(mActivity, request, LiveLocationFeature::onConsentAnswered));
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
