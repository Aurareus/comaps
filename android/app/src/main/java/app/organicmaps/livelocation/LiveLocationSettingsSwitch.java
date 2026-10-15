package app.organicmaps.livelocation;

import android.app.Activity;
import android.content.Context;
import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.preference.TwoStatePreference;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

/**
 * Live location (NLL): the switch in Settings → Live location sharing (docs/LIVE_LOCATION.md §8.4,
 * §11.1). Turning it on the first time shows what relays can see; turning it off keeps the contacts and
 * offers to delete them.
 */
public final class LiveLocationSettingsSwitch
{
  private LiveLocationSettingsSwitch() {}

  /** `onChanged` runs once the feature has been turned on or off. */
  public static void bind(@NonNull Fragment fragment, @NonNull TwoStatePreference preference,
                          @NonNull Runnable onChanged)
  {
    final Context context = fragment.requireContext().getApplicationContext();
    preference.setVisible(LiveLocation.isSupported());
    preference.setChecked(LiveLocationFeature.isEnabled(context));
    preference.setOnPreferenceChangeListener((pref, value) -> {
      final boolean enabled = (Boolean) value;
      LiveLocationFeature.setEnabled(context, enabled);
      if (enabled && !LiveLocationFeature.wasExplained(context))
        fragment.startActivity(LiveLocationActivity.explanationIntent(context));
      else if (!enabled)
        offerDeletion(fragment.requireActivity());
      onChanged.run();
      return true;
    });
  }

  private static void offerDeletion(@NonNull Activity activity)
  {
    new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.live_location_turned_off_title)
        .setMessage(R.string.live_location_turned_off_message)
        .setPositiveButton(R.string.live_location_keep, null)
        .setNegativeButton(R.string.live_location_delete_all, (dialog, which) -> confirmDeletion(activity))
        .show();
  }

  static void confirmDeletion(@NonNull Activity activity)
  {
    confirmDeletion(activity, () -> {});
  }

  /** `onDeleted` runs once the data is gone. */
  static void confirmDeletion(@NonNull Activity activity, @NonNull Runnable onDeleted)
  {
    new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.live_location_delete_all)
        .setMessage(R.string.live_location_delete_all_confirm)
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(R.string.live_location_delete,
                           (dialog, which) -> {
                             LiveLocationFeature.deleteAllData(activity.getApplicationContext());
                             onDeleted.run();
                           })
        .show();
  }
}
