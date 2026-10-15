package app.organicmaps.livelocation;

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;
import static android.Manifest.permission.ACCESS_FINE_LOCATION;
import static android.Manifest.permission.POST_NOTIFICATIONS;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Live location (NLL): "Share my location" (docs/LIVE_LOCATION.md §11.3): contacts and a duration.
 * Also adds people to the current share, and resumes one after the process died. Sharing starts only
 * with precise location and a notification that can be seen.
 */
public class ShareFragment extends LiveLocationFragment
{
  static final String ARG_ADD = "add";
  private static final String STATE_SELECTED = "selected";
  private static final String STATE_DURATION = "duration";
  private static final long[] DURATIONS = {15 * 60, 60 * 60, 8 * 60 * 60, 0};
  private static final int[] DURATION_NAMES = {R.string.live_location_15_min, R.string.live_location_1_hour,
                                               R.string.live_location_8_hours, R.string.live_location_until_stopped};

  private final Set<String> mSelected = new LinkedHashSet<>();
  // Resuming: each recipient's end, as it was.
  private final Map<String, Long> mResumeUntil = new HashMap<>();
  private int mDuration = 1;
  private boolean mAdd;
  private boolean mResume;
  private boolean mAskedNotifications;
  @Nullable
  private MaterialButton mStart;
  private ActivityResultLauncher<String[]> mLocationPermission;
  private ActivityResultLauncher<String> mNotificationPermission;

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    final Bundle args = getArguments();
    mAdd = args != null && args.getBoolean(ARG_ADD);
    mResume =
        args != null && LiveLocationActivity.SCREEN_RESUME.equals(args.getString(LiveLocationActivity.EXTRA_SCREEN));
    if (mResume)
    {
      for (Recipient recipient : LiveLocation.getSharing().resumable)
        mResumeUntil.put(recipient.contactId, recipient.until);
    }
    if (savedInstanceState != null)
    {
      final ArrayList<String> selected = savedInstanceState.getStringArrayList(STATE_SELECTED);
      if (selected != null)
        mSelected.addAll(selected);
      mDuration = savedInstanceState.getInt(STATE_DURATION, 1);
    }
    else
    {
      mSelected.addAll(mResumeUntil.keySet());
    }

    mLocationPermission =
        registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> {
          if (LocationUtils.checkFineLocationPermission(requireContext()))
            start();
          else
            LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_location_needed));
        });
    mNotificationPermission =
        registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> start());
  }

  @Override
  public void onSaveInstanceState(@NonNull Bundle outState)
  {
    super.onSaveInstanceState(outState);
    outState.putStringArrayList(STATE_SELECTED, new ArrayList<>(mSelected));
    outState.putInt(STATE_DURATION, mDuration);
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Context context = requireContext();
    final Sharing sharing = LiveLocation.getSharing();
    final boolean adding = mAdd || sharing.active;
    final Set<String> current = new LinkedHashSet<>();
    if (adding)
      for (Recipient recipient : sharing.recipients)
        current.add(recipient.contactId);

    views.header(getString(R.string.live_location_share_with));
    for (Contact contact : LiveLocation.getContacts())
    {
      if (current.contains(contact.id))
        continue;
      final List<String> warnings = new ArrayList<>();
      if (contact.flagged)
        warnings.add(getString(R.string.live_location_flagged_warning, contact.name));
      else if (!contact.verified)
        warnings.add(getString(R.string.live_location_unverified_warning, contact.name));
      if (contact.waiting)
        warnings.add(getString(R.string.live_location_waiting_warning, contact.name));
      // Flagged contacts cannot be picked until their code has been compared (§11.3).
      if (contact.flagged)
        mSelected.remove(contact.id);
      views.check(contact.name, String.join("\n", warnings), mSelected.contains(contact.id), !contact.flagged,
                  (box, checked) -> {
                    if (checked)
                      mSelected.add(contact.id);
                    else
                      mSelected.remove(contact.id);
                    updateStart();
                  });
    }

    if (mResume)
    {
      final long until = LiveLocationText.latestUntil(LiveLocation.getSharing().resumable);
      views.text(until == 0 ? getString(R.string.live_location_until_you_stop)
                            : getString(R.string.live_location_until, LiveLocationText.time(context, until)));
    }
    else
    {
      views.header(getString(R.string.live_location_for));
      views.row(getString(DURATION_NAMES[mDuration]), null, null, v -> pickDuration());
    }
    mStart = views.button(getString(R.string.live_location_start), v -> start());
    updateStart();
  }

  private void updateStart()
  {
    if (mStart != null)
      mStart.setEnabled(!mSelected.isEmpty());
  }

  private void pickDuration()
  {
    final CharSequence[] names = new CharSequence[DURATION_NAMES.length];
    for (int i = 0; i < names.length; ++i)
      names[i] = getString(DURATION_NAMES[i]);
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(R.string.live_location_for)
        .setSingleChoiceItems(names, mDuration,
                              (dialog, which) -> {
                                mDuration = which;
                                dialog.dismiss();
                                refresh();
                              })
        .show();
  }

  private void start()
  {
    final Context context = requireContext();
    if (mSelected.isEmpty())
      return;
    if (!LocationUtils.checkFineLocationPermission(context))
    {
      mLocationPermission.launch(new String[] {ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION});
      return;
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !mAskedNotifications
        && ContextCompat.checkSelfPermission(context, POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
    {
      mAskedNotifications = true;
      mNotificationPermission.launch(POST_NOTIFICATIONS);
      return;
    }
    if (!LiveLocationService.canNotify(context))
    {
      new MaterialAlertDialogBuilder(requireActivity())
          .setMessage(R.string.live_location_notifications_needed)
          .setNegativeButton(R.string.cancel, null)
          .setPositiveButton(R.string.live_location_open_settings, (dialog, which) -> openNotificationSettings())
          .show();
      return;
    }

    final long now = System.currentTimeMillis() / 1000;
    final List<Recipient> recipients = new ArrayList<>();
    final Sharing sharing = LiveLocation.getSharing();
    final boolean adding = mAdd || sharing.active;
    if (adding)
      recipients.addAll(sharing.recipients);
    for (String id : mSelected)
    {
      long until = DURATIONS[mDuration] == 0 ? 0 : now + DURATIONS[mDuration];
      if (mResume)
      {
        final Long before = mResumeUntil.get(id);
        until = before != null ? before : 0;
        if (until != 0 && until <= now)
          continue; // that share is over
      }
      recipients.add(new Recipient(id, until));
    }
    final boolean started = adding ? LiveLocation.changeSharing(recipients)
                                   : !recipients.isEmpty() && LiveLocation.startSharing(recipients);
    if (!started)
    {
      LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_share_failed));
      return;
    }
    LiveLocationService.start(context);
    if (mResume || getParentFragmentManager().getBackStackEntryCount() == 0)
      requireActivity().finish();
    else
      getParentFragmentManager().popBackStack();
  }

  private void openNotificationSettings()
  {
    final Context context = requireContext();
    final Intent intent;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
      intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                   .putExtra(Settings.EXTRA_APP_PACKAGE, context.getPackageName());
    else
      intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                   .setData(Uri.fromParts("package", context.getPackageName(), null));
    startActivity(intent);
  }
}
