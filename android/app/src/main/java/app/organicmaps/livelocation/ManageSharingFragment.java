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
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Consent;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Live location (NLL): "Manage sharing" (docs/LIVE_LOCATION.md §11.3), for starting a share as well as
 * changing it. Those it goes to are ticked, at the top; unticking one stops sharing with them. Below, "For"
 * and everyone else; ticking one shares with them for that long. Each change of recipients replaces the
 * stream, with a new key and up to two minutes of silence, so people ticked within a moment of each other
 * are added together, and at the latest when the screen goes. A share starts only with precise location
 * and a notification that can be seen. It also resumes a share after the process died.
 */
public class ManageSharingFragment extends LiveLocationFragment
{
  private static final long ADD_DELAY_MS = 2_500;
  private static final String STATE_SECONDS = "seconds";
  private static final String STATE_UNTIL = "until";

  // Ticked and not added yet: contact id -> the share's end (0: until stopped).
  private final Map<String, Long> mPending = new LinkedHashMap<>();
  @NonNull
  private ShareDuration mDuration = ShareDuration.DEFAULT;
  private final Handler mHandler = new Handler(Looper.getMainLooper());
  private final Runnable mAdd = this::addPending;
  private boolean mResume;
  private boolean mAskedNotifications;
  // What waits for the permissions.
  @Nullable
  private Runnable mAfterPermissions;
  private ActivityResultLauncher<String[]> mLocationPermission;
  private ActivityResultLauncher<String> mNotificationPermission;

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    final Bundle args = getArguments();
    mResume = savedInstanceState == null && args != null
           && LiveLocationActivity.SCREEN_RESUME.equals(args.getString(LiveLocationActivity.EXTRA_SCREEN));
    // Ticks are not kept with the state: the screen added them when it stopped, which before Android 9 comes
    // after the state is saved.
    if (savedInstanceState != null)
      mDuration = new ShareDuration(savedInstanceState.getLong(STATE_SECONDS, ShareDuration.DEFAULT.mSeconds),
                                    savedInstanceState.getLong(STATE_UNTIL, 0));

    mLocationPermission =
        registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> {
          if (LocationUtils.checkFineLocationPermission(requireContext()))
            continueAfterPermissions();
          else
          {
            mAfterPermissions = null;
            LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_location_needed));
            refresh();
          }
        });
    mNotificationPermission = registerForActivityResult(new ActivityResultContracts.RequestPermission(),
                                                        granted -> continueAfterPermissions());
  }

  @Override
  public void onSaveInstanceState(@NonNull Bundle outState)
  {
    super.onSaveInstanceState(outState);
    outState.putLong(STATE_SECONDS, mDuration.mSeconds);
    outState.putLong(STATE_UNTIL, mDuration.mUntil);
  }

  @Override
  public void onStart()
  {
    super.onStart();
    if (mResume)
    {
      mResume = false;
      resume(true);
    }
  }

  @Override
  public void onStop()
  {
    addPending(); // the screen goes: nothing ticked is left behind
    super.onStop();
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Context context = requireContext();
    final Sharing sharing = LiveLocation.getSharing();
    final List<Contact> contacts = LiveLocation.getContacts();
    // Also when the map's offer led here for the permissions, and the user comes back from the settings.
    if (!sharing.active && !sharing.resumable.isEmpty())
    {
      views.text(LiveLocationDialogs.resumeMessage(context, sharing));
      views.button(getString(R.string.live_location_resume_button), v -> resume(false));
      views.outlinedButton(getString(R.string.live_location_dont_resume), v -> LiveLocation.dismissResume());
    }
    if (sharing.live)
      views.text(getString(R.string.live_location_live_now));

    final Set<String> sharedWith = new HashSet<>(mPending.keySet());
    for (Recipient recipient : sharing.recipients)
      sharedWith.add(recipient.contactId);
    if (!sharedWith.isEmpty())
      views.header(getString(R.string.live_location_currently_sharing_with));
    for (Recipient recipient : sharing.recipients)
    {
      final Contact contact = LiveLocation.getContact(recipient.contactId);
      views.check(contact != null ? contact.name : "?", LiveLocationText.until(context, recipient.until), true, true,
                  (box, checked) -> {
                    if (!checked)
                      remove(recipient.contactId);
                  });
    }
    for (Map.Entry<String, Long> pending : mPending.entrySet())
    {
      final Contact contact = LiveLocation.getContact(pending.getKey());
      if (contact == null || LiveLocationShares.isRecipient(sharing, contact.id))
        continue;
      views.check(contact.name, getString(R.string.live_location_starting), true, true, (box, checked) -> {
        if (!checked)
        {
          mPending.remove(contact.id);
          refreshLater();
        }
      });
    }

    final List<Contact> others = new ArrayList<>();
    for (Contact contact : contacts)
      if (!sharedWith.contains(contact.id))
        others.add(contact);
    if (contacts.isEmpty())
      views.text(getString(R.string.live_location_no_contacts));
    if (!others.isEmpty())
    {
      views.header(getString(R.string.live_location_start_sharing_with));
      views.row(getString(R.string.live_location_for), mDuration.label(context), null,
                v -> LiveLocationDialogs.pickDuration(this, mDuration, duration -> {
                  mDuration = duration;
                  refresh();
                }));
    }
    for (Contact contact : others)
    {
      views.check(contact.name, warnings(contact), false, !contact.flagged, (box, checked) -> {
        if (checked)
          tick(contact);
      });
    }

    if (sharing.active)
      views.redButton(getString(R.string.live_location_stop_all), v -> {
        mPending.clear();
        LiveLocation.stopSharing();
      });
  }

  @NonNull
  private String warnings(@NonNull Contact contact)
  {
    final List<String> warnings = new ArrayList<>();
    // Flagged contacts cannot be picked until their code has been compared (§11.2).
    if (contact.flagged)
      warnings.add(getString(R.string.live_location_flagged_warning, contact.name));
    else if (!contact.verified)
      warnings.add(getString(R.string.live_location_unverified_warning, contact.name));
    if (contact.waiting)
      warnings.add(getString(R.string.live_location_waiting_warning, contact.name));
    if (!contact.blockedRelay.isEmpty())
      warnings.add(getString(R.string.live_location_blocked, contact.name, contact.blockedRelay));
    return String.join("\n", warnings);
  }

  /** A contact ticked. Nothing would reach one whose relays are all refused: that relay first. */
  private void tick(@NonNull Contact contact)
  {
    if (contact.blockedRelay.isEmpty())
    {
      add(contact.id);
      return;
    }
    refreshLater();
    LiveLocationDialogs.showConsent(
        requireActivity(), new ConsentRequest(contact.blockedRelay, contact.name, ConsentRequest.Purpose.Sending),
        consent -> {
          if (consent == Consent.Allow && isAdded())
            add(contact.id);
        });
  }

  /** Shared with soon, together with whoever else is ticked meanwhile. */
  private void add(@NonNull String contactId)
  {
    final Runnable add = () ->
    {
      final long now = System.currentTimeMillis() / 1000;
      final long until = mDuration.until(now);
      if (until != 0 && until <= now)
      {
        // "Until…" a time that has passed since it was picked.
        LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_time_passed));
        refreshLater();
        return;
      }
      mPending.put(contactId, until);
      mHandler.removeCallbacks(mAdd);
      mHandler.postDelayed(mAdd, ADD_DELAY_MS);
      refreshLater();
    };
    if (LiveLocation.getSharing().active || !mPending.isEmpty())
      add.run();
    else
    {
      refreshLater(); // unticked until the permissions are there
      withPermissions(add);
    }
  }

  private void addPending()
  {
    mHandler.removeCallbacks(mAdd);
    if (mPending.isEmpty())
      return;
    final long now = System.currentTimeMillis() / 1000;
    final Sharing sharing = LiveLocation.getSharing();
    final List<Recipient> recipients = new ArrayList<>(sharing.active ? sharing.recipients : List.of());
    for (Map.Entry<String, Long> pending : mPending.entrySet())
    {
      final long until = pending.getValue();
      if ((until == 0 || until > now) && !LiveLocationShares.isRecipient(sharing, pending.getKey()))
        recipients.add(new Recipient(pending.getKey(), until));
    }
    mPending.clear();
    if (recipients.isEmpty())
      return;
    final boolean started =
        sharing.active ? LiveLocation.changeSharing(recipients) : LiveLocation.startSharing(recipients);
    if (!started && isAdded())
      LiveLocationDialogs.showMessage(
          requireActivity(), null,
          getString(sharing.active ? R.string.live_location_change_failed : R.string.live_location_share_failed));
    else if (started && !sharing.active)
      LiveLocationService.start(requireContext());
    refreshLater();
  }

  /** Unticked: stops sharing with them at once, adding whoever is ticked in the same change. */
  private void remove(@NonNull String contactId)
  {
    final Map<String, Long> adding = new LinkedHashMap<>(mPending);
    mPending.clear();
    mHandler.removeCallbacks(mAdd);
    if (!LiveLocationShares.stopSharingWith(contactId, adding))
      LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_change_failed));
    refreshLater();
  }

  /**
   * After the process died while sharing: the same people, with the same ends, once the permissions are
   * there. From the map's offer, the screen then closes.
   */
  private void resume(boolean thenClose)
  {
    final List<Recipient> resumable = LiveLocation.getSharing().resumable;
    final long now = System.currentTimeMillis() / 1000;
    final List<Recipient> recipients = new ArrayList<>();
    for (Recipient recipient : resumable)
      if (recipient.until == 0 || recipient.until > now)
        recipients.add(recipient);
    if (recipients.isEmpty())
    {
      if (!resumable.isEmpty())
      {
        // Every end has passed since the offer was made.
        LiveLocation.dismissResume();
        LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_resume_ended));
      }
      return;
    }
    withPermissions(() -> {
      if (!LiveLocation.startSharing(recipients))
      {
        LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_share_failed));
        return;
      }
      LiveLocationService.start(requireContext());
      if (thenClose)
        requireActivity().finish();
    });
  }

  /** Runs `then` once sharing may start: precise location, and a notification that can be seen. */
  private void withPermissions(@NonNull Runnable then)
  {
    final Context context = requireContext();
    mAfterPermissions = then;
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
    mAfterPermissions = null;
    if (!LiveLocationService.canNotify(context))
    {
      new MaterialAlertDialogBuilder(requireActivity())
          .setMessage(R.string.live_location_notifications_needed)
          .setNegativeButton(R.string.cancel, null)
          .setPositiveButton(R.string.live_location_open_settings, (dialog, which) -> openNotificationSettings())
          .show();
      return;
    }
    then.run();
  }

  private void continueAfterPermissions()
  {
    final Runnable then = mAfterPermissions;
    if (then != null && isAdded())
      withPermissions(then);
  }

  /** Builds the screen again after the event being handled, such as a tick, is over. */
  private void refreshLater()
  {
    mHandler.post(this::refresh);
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
