package app.organicmaps.livelocation;

import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import app.organicmaps.R;
import app.organicmaps.maplayer.MapButtonsController;
import app.organicmaps.maplayer.MapButtonsViewModel;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;
import com.google.android.material.chip.Chip;

/**
 * Live location (NLL): what the map screen shows of it (docs/LIVE_LOCATION.md §11.3): a chip while
 * the user shares, which opens "Manage sharing"; the offer to resume a share after the process died;
 * and relay consent questions.
 */
public final class LiveLocationMapUi implements LiveLocation.Listener, LiveLocationFeature.ConsentPresenter
{
  @NonNull
  private final AppCompatActivity mActivity;
  @NonNull
  private final ViewGroup mContainer;
  @NonNull
  private final MapButtonsViewModel mMapButtons;
  @Nullable
  private Chip mChip;
  @Nullable
  private AlertDialog mDialog;
  private boolean mStarted;

  /** `container`: the RelativeLayout over the map. */
  public LiveLocationMapUi(@NonNull AppCompatActivity activity, @NonNull ViewGroup container)
  {
    mActivity = activity;
    mContainer = container;
    mMapButtons = new ViewModelProvider(activity).get(MapButtonsViewModel.class);
    // Routing's panels and an open place page take the top of the map.
    mMapButtons.getLayoutMode().observe(activity, mode -> updateChip());
    mMapButtons.getButtonsHidden().observe(activity, hidden -> updateChip());
    mMapButtons.getTopButtonsMarginTop().observe(activity, margin -> updateChip());
  }

  public void onStart()
  {
    if (!LiveLocationFeature.isEnabled(mActivity))
    {
      updateChip();
      return;
    }
    mStarted = true;
    LiveLocation.addListener(this);
    LiveLocationFeature.attachConsentPresenter(this);
    updateChip();
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
    updateChip();
    offerResume(sharing);
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

  private void updateChip()
  {
    final Sharing sharing = LiveLocation.getSharing();
    final boolean visible = mStarted && sharing.active
                         && mMapButtons.getLayoutMode().getValue() == MapButtonsController.LayoutMode.regular
                         && !Boolean.TRUE.equals(mMapButtons.getButtonsHidden().getValue());
    if (!visible)
    {
      if (mChip != null)
        mChip.setVisibility(android.view.View.GONE);
      return;
    }
    if (mChip == null)
    {
      mChip = new Chip(mActivity);
      mChip.setChipIconResource(R.drawable.ic_groups);
      mChip.setChipIconVisible(true);
      mChip.setElevation(mActivity.getResources().getDimension(R.dimen.margin_quarter));
      mChip.setOnClickListener(v -> mActivity.startActivity(LiveLocationActivity.manageIntent(mActivity)));
      final RelativeLayout.LayoutParams params =
          new RelativeLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
      params.addRule(RelativeLayout.ALIGN_PARENT_TOP);
      params.addRule(RelativeLayout.CENTER_HORIZONTAL);
      mContainer.addView(mChip, params);
    }
    final Integer margin = mMapButtons.getTopButtonsMarginTop().getValue();
    final ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) mChip.getLayoutParams();
    params.topMargin =
        margin != null && margin >= 0 ? margin : mActivity.getResources().getDimensionPixelSize(R.dimen.margin_base);
    mChip.setLayoutParams(params);
    final int count = sharing.recipients.size();
    mChip.setText(mActivity.getResources().getQuantityString(R.plurals.live_location_sharing_with_count, count, count));
    mChip.setVisibility(android.view.View.VISIBLE);
  }
}
