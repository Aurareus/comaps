package app.organicmaps.livelocation;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.preference.PreferenceManager;
import app.organicmaps.MwmApplication;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.LocationUtils;
import app.organicmaps.sdk.util.log.Logger;
import java.util.ArrayDeque;

/**
 * Live location (NLL): the feature's switch and lifecycle (docs/LIVE_LOCATION.md §8.4). While it is
 * off, nothing of it runs: no native thread, no file, no network, but for telling contacts that the
 * share it stopped has ended, once there is a network, for a week at most (LiveLocationDeliveryWork).
 * It also holds what any screen may have to show: relay consent questions and what the user must be
 * told, which the screen in front presents one at a time (§11.4), and whether the store could not be
 * read.
 */
@MainThread
public final class LiveLocationFeature
{
  private static final String TAG = LiveLocationFeature.class.getSimpleName();
  private static final String PREF_EXPLAINED = "LiveLocationExplained";
  private static final String PREF_OFF_SINCE = "LiveLocationOffSince";
  // Turned off, the feature still tells contacts that a share it stopped has ended, for as long as a deleted
  // contact is told (§8.5).
  private static final long DELIVER_WHILE_OFF_SECONDS = 7 * 24 * 3600;

  /** A screen that can ask the user about a relay, and tell the user what they must know. */
  public interface Presenter
  {
    /** Call {@link #onPresented()} once the user has answered. */
    void presentConsent(@NonNull ConsentRequest request);
    /** Call {@link #onPresented()} once the user has read it. */
    void presentMessage(@StringRes int message);
  }

  // Consent requests, and messages (string resources), to present in order.
  private static final ArrayDeque<Object> sPending = new ArrayDeque<>();
  @Nullable
  private static Presenter sPresenter;
  private static boolean sPresenting;
  private static boolean sStoreError;
  private static boolean sToldWriteFailed; // once per run
  private static long sDeliveryDue; // as the core last said

  private static final LiveLocation.Listener sListener = new LiveLocation.Listener() {
    @Override
    public void onConsentNeeded(@NonNull ConsentRequest request)
    {
      for (Object pending : sPending)
        if (pending instanceof ConsentRequest queued && queued.url.equals(request.url))
          return;
      sPending.add(request);
      presentNext();
    }

    @Override
    public void onStoreError()
    {
      sStoreError = true;
    }

    @Override
    public void onWriteFailed()
    {
      if (sToldWriteFailed)
        return;
      sToldWriteFailed = true;
      tell(R.string.live_location_not_saved);
    }

    @Override
    public void onSharing(@NonNull Sharing sharing)
    {
      updateDeliveryJob();
    }

    @Override
    public void onDeliveryDue(long at)
    {
      sDeliveryDue = at;
      updateDeliveryJob();
    }
  };

  private LiveLocationFeature() {}

  @AnyThread
  public static boolean isEnabled(@NonNull Context context)
  {
    return LiveLocation.isSupported() && prefs(context).getBoolean(key(context), false);
  }

  public static void setEnabled(@NonNull Context context, boolean enabled)
  {
    // Below Android 7 the feature does not exist: nothing offers it, and nothing turns it on.
    if (enabled == isEnabled(context) || (enabled && !LiveLocation.isSupported()))
      return;
    final SharedPreferences.Editor editor = prefs(context).edit().putBoolean(key(context), enabled);
    if (enabled)
      editor.remove(PREF_OFF_SINCE);
    else
      editor.putLong(PREF_OFF_SINCE, System.currentTimeMillis() / 1000);
    editor.apply();
    if (enabled)
      start(context);
    else
      stop(context);
  }

  /** Whether what no relay has accepted may still be sent: while the feature is on, and a week after it went off. */
  @AnyThread
  static boolean mayDeliver(@NonNull Context context)
  {
    if (isEnabled(context))
      return true;
    final SharedPreferences prefs = prefs(context);
    final long now = System.currentTimeMillis() / 1000;
    long since = prefs.getLong(PREF_OFF_SINCE, 0);
    if (since == 0)
    {
      since = now; // turned off by an earlier build
      prefs.edit().putLong(PREF_OFF_SINCE, since).apply();
    }
    return now < since + DELIVER_WHILE_OFF_SECONDS;
  }

  /** Whether the explanation screen (§11.6) was shown since the feature was first turned on. */
  public static boolean wasExplained(@NonNull Context context)
  {
    return prefs(context).getBoolean(PREF_EXPLAINED, false);
  }

  public static void setExplained(@NonNull Context context)
  {
    prefs(context).edit().putBoolean(PREF_EXPLAINED, true).apply();
  }

  /** Once the app's core has started: starts the feature if it is on. */
  public static void onCoreReady(@NonNull Context context)
  {
    if (isEnabled(context))
      start(context);
  }

  public static void onForeground(@NonNull Context context)
  {
    LiveLocation.setForeground(true);
    updateDeliveryJob();
    // Location runs at the map's pace again.
    if (LocationUtils.checkLocationPermission(context))
      MwmApplication.from(context).getLocationHelper().setSharingPace(0, false);
  }

  public static void onBackground()
  {
    LiveLocation.setForeground(false);
    updateDeliveryJob();
  }

  /** The store could not be read: the screens offer to delete the live location data. */
  public static boolean hasStoreError()
  {
    return sStoreError;
  }

  public static void deleteAllData(@NonNull Context context)
  {
    LiveLocationDeliveryWork.schedule(context, 0); // nothing left to send
    LiveLocation.deleteAllData(context);
    sStoreError = false;
  }

  /** The share stopped because its notification could not be seen: the screen in front, or the next one, says so. */
  static void onStoppedUnseen()
  {
    tell(R.string.live_location_stopped_unseen);
  }

  /** The share stopped as it started, because Android did not run its service: the same. */
  static void onStartFailed()
  {
    tell(R.string.live_location_share_failed);
  }

  public static void attachPresenter(@NonNull Presenter presenter)
  {
    sPresenter = presenter;
    sPresenting = false;
    presentNext();
  }

  public static void detachPresenter(@NonNull Presenter presenter)
  {
    if (sPresenter != presenter)
      return;
    sPresenter = null;
    sPresenting = false;
  }

  public static void onPresented()
  {
    if (!sPending.isEmpty())
      sPending.removeFirst();
    sPresenting = false;
    presentNext();
  }

  private static void tell(@StringRes int message)
  {
    if (!sPending.contains(message))
      sPending.add(message);
    presentNext();
  }

  private static void presentNext()
  {
    if (sPresenter == null || sPresenting || sPending.isEmpty())
      return;
    sPresenting = true;
    if (sPending.getFirst() instanceof ConsentRequest request)
      sPresenter.presentConsent(request);
    else
      sPresenter.presentMessage((Integer) sPending.getFirst());
  }

  /**
   * The delivery job is there only while the app is neither on screen nor sharing. On screen or sharing, the
   * core runs and sends again by itself what no relay has accepted, and a job would only repeat that.
   * Otherwise the job sends it, also once the process has ended, or while the phone sleeps and the core's own
   * timers stand still.
   */
  private static void updateDeliveryJob()
  {
    if (!LiveLocation.isRunning())
      return; // off: the job runs from when the feature was turned off, until it is turned on again
    final boolean coreSends =
        ProcessLifecycleOwner.get().getLifecycle().getCurrentState().isAtLeast(Lifecycle.State.STARTED)
        || LiveLocation.getSharing().active;
    LiveLocationDeliveryWork.schedule(MwmApplication.sInstance, coreSends ? 0 : sDeliveryDue);
  }

  private static void start(@NonNull Context context)
  {
    Logger.i(TAG, "Starting");
    LiveLocationService.createNotificationChannel(context);
    LiveLocation.addListener(sListener);
    sStoreError = !LiveLocation.start(context);
    LiveLocationRatchetWork.schedule(context);
  }

  private static void stop(@NonNull Context context)
  {
    Logger.i(TAG, "Stopping");
    LiveLocationRatchetWork.cancel(context);
    LiveLocationService.stop(context);
    LiveLocation.stop();
    LiveLocation.removeListener(sListener);
    // A share it stopped ends for its recipients too, also when no relay could be reached just now.
    LiveLocationDeliveryWork.schedule(context, System.currentTimeMillis() / 1000);
    sPending.clear();
    sPresenting = false;
    sStoreError = false;
  }

  @AnyThread
  @NonNull
  private static SharedPreferences prefs(@NonNull Context context)
  {
    return PreferenceManager.getDefaultSharedPreferences(context);
  }

  @AnyThread
  @NonNull
  private static String key(@NonNull Context context)
  {
    return context.getString(R.string.pref_live_location);
  }
}
