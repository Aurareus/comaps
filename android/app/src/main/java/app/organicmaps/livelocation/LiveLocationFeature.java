package app.organicmaps.livelocation;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.preference.PreferenceManager;
import app.organicmaps.MwmApplication;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.util.LocationUtils;
import app.organicmaps.sdk.util.log.Logger;
import java.util.ArrayDeque;

/**
 * Live location (NLL): the feature's switch and lifecycle (docs/LIVE_LOCATION.md §8.4). While it is
 * off, nothing of it runs: no native thread, no file, no network. It also holds what any screen may
 * have to show: relay consent questions and what the user must be told, which the screen in front
 * presents one at a time (§11.4), and whether the store could not be read.
 */
@MainThread
public final class LiveLocationFeature
{
  private static final String TAG = LiveLocationFeature.class.getSimpleName();
  private static final String PREF_EXPLAINED = "LiveLocationExplained";

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
    prefs(context).edit().putBoolean(key(context), enabled).apply();
    if (enabled)
      start(context);
    else
      stop(context);
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
    // Location runs at the map's pace again.
    if (LocationUtils.checkLocationPermission(context))
      MwmApplication.from(context).getLocationHelper().setSharingPace(0, false);
  }

  public static void onBackground()
  {
    LiveLocation.setForeground(false);
  }

  /** The store could not be read: the screens offer to delete the live location data. */
  public static boolean hasStoreError()
  {
    return sStoreError;
  }

  public static void deleteAllData(@NonNull Context context)
  {
    LiveLocation.deleteAllData(context);
    sStoreError = false;
  }

  /** The share stopped because its notification could not be seen: the screen in front, or the next one, says so. */
  static void onStoppedUnseen()
  {
    tell(R.string.live_location_stopped_unseen);
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
