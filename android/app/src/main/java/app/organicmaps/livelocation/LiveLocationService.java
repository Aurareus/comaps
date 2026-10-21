package app.organicmaps.livelocation;

import static android.Manifest.permission.POST_NOTIFICATIONS;

import android.app.ForegroundServiceStartNotAllowedException;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.location.Location;
import android.os.BatteryManager;
import android.os.Build;
import android.os.IBinder;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationChannelCompat;
import androidx.core.app.NotificationChannelGroupCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.app.ServiceCompat;
import androidx.core.content.ContextCompat;
import app.organicmaps.MwmApplication;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.LocationMode;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.location.LocationHelper;
import app.organicmaps.sdk.location.LocationListener;
import app.organicmaps.sdk.util.LocationUtils;
import app.organicmaps.sdk.util.log.Logger;
import java.util.List;

/**
 * Live location (NLL): the foreground service that runs while the user shares their location
 * (docs/LIVE_LOCATION.md §10.2, §11.3). It passes fixes and the battery level to the core, and sets
 * the location pace while a share alone keeps location running in the background.
 *
 * <p>No silent sharing: a share runs only while its notification can be seen. The service checks
 * before passing on each fix and when the system says notifications were blocked, and stops the
 * share otherwise. A swiped-away notification is posted again.
 */
public class LiveLocationService extends Service implements LocationListener, LiveLocation.Listener
{
  private static final String TAG = LiveLocationService.class.getSimpleName();
  public static final String CHANNEL_ID = "LIVE_LOCATION";
  private static final int NOTIFICATION_ID = 54322;
  private static final String ACTION_STOP = "app.organicmaps.livelocation.STOP";
  private static final String ACTION_REPOST = "app.organicmaps.livelocation.REPOST";
  // The location pace of a share alone in the background (§10.3).
  private static final long LIVE_INTERVAL_MS = 2_000;
  private static final long IDLE_INTERVAL_MS = 30_000;

  private static boolean sRunning;
  private boolean mForeground;

  private final BroadcastReceiver mBatteryReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent)
    {
      // Plugged in, the share goes on whatever the level, and viewers are not told the battery is low.
      final boolean charging = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0;
      final int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
      final int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
      if (level >= 0 && scale > 0)
        LiveLocation.onBatteryLevel(level * 100 / scale, charging);
    }
  };

  private final BroadcastReceiver mBlockedReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent)
    {
      checkNotifications();
    }
  };

  public static boolean isRunning()
  {
    return sRunning;
  }

  public static void createNotificationChannel(@NonNull Context context)
  {
    // Default importance, for an icon in the status bar, but without sound or vibration.
    final NotificationChannelCompat channel =
        new NotificationChannelCompat.Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_DEFAULT)
            .setName(context.getString(R.string.live_location_channel))
            .setDescription(context.getString(R.string.live_location_channel_description))
            .setSound(null, null)
            .setVibrationEnabled(false)
            .setLightsEnabled(false)
            .setShowBadge(false)
            .build();
    NotificationManagerCompat.from(context).createNotificationChannel(channel);
  }

  /** Whether the sharing notification can be seen: notifications on, the channel and its group not blocked. */
  public static boolean canNotify(@NonNull Context context)
  {
    final NotificationManagerCompat manager = NotificationManagerCompat.from(context);
    if (!manager.areNotificationsEnabled())
      return false;
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O)
      return true;
    final NotificationChannelCompat channel = manager.getNotificationChannelCompat(CHANNEL_ID);
    if (channel == null || channel.getImportance() == NotificationManagerCompat.IMPORTANCE_NONE)
      return false;
    if (channel.getGroup() != null)
    {
      final NotificationChannelGroupCompat group = manager.getNotificationChannelGroupCompat(channel.getGroup());
      return group == null || !group.isBlocked();
    }
    return true;
  }

  /** Once a share has started, from the foreground: Android 12 allows no other time. */
  public static void start(@NonNull Context context)
  {
    ContextCompat.startForegroundService(context, new Intent(context, LiveLocationService.class));
  }

  public static void stop(@NonNull Context context)
  {
    context.stopService(new Intent(context, LiveLocationService.class));
  }

  /** The app went to the background with only a share needing location: the share's pace. */
  public static void useSharingPace(@NonNull Context context)
  {
    if (!LocationUtils.checkLocationPermission(context))
      return;
    final LocationMode mode = LiveLocation.getLocationMode();
    MwmApplication.from(context).getLocationHelper().setSharingPace(
        mode == LocationMode.Live ? LIVE_INTERVAL_MS : IDLE_INTERVAL_MS, mode != LocationMode.Live);
  }

  @Nullable
  @Override
  public IBinder onBind(Intent intent)
  {
    return null;
  }

  @Override
  public void onCreate()
  {
    super.onCreate();
    sRunning = true;
    LiveLocation.addListener(this);
    ContextCompat.registerReceiver(this, mBatteryReceiver, new IntentFilter(Intent.ACTION_BATTERY_CHANGED),
                                   ContextCompat.RECEIVER_NOT_EXPORTED);
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
    {
      final IntentFilter filter = new IntentFilter(NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED);
      filter.addAction(NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED);
      filter.addAction(NotificationManager.ACTION_NOTIFICATION_CHANNEL_GROUP_BLOCK_STATE_CHANGED);
      ContextCompat.registerReceiver(this, mBlockedReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
    }
  }

  @Override
  public int onStartCommand(@Nullable Intent intent, int flags, int startId)
  {
    final String action = intent != null ? intent.getAction() : null;
    if (ACTION_STOP.equals(action) || ACTION_REPOST.equals(action))
    {
      if (ACTION_STOP.equals(action))
      {
        Logger.i(TAG, "Stopped from the notification");
        LiveLocation.stopSharing(); // the share's end stops the service
      }
      else if (LiveLocation.getSharing().active)
      {
        updateNotification();
      }
      if (!mForeground)
        stopSelf(); // a stale notification's intent started it
      return START_NOT_STICKY;
    }

    if (!MwmApplication.from(this).getOrganicMaps().arePlatformAndCoreInitialized() || !LiveLocation.isRunning()
        || !LiveLocation.getSharing().active)
    {
      Logger.w(TAG, "Nothing to share");
      stopSelf();
      return START_NOT_STICKY;
    }
    if (!LocationUtils.checkFineLocationPermission(this) || !canNotify(this))
    {
      Logger.w(TAG, "No location permission, or the notification cannot be seen: the share stops");
      LiveLocation.stopSharing();
      stopSelf();
      return START_NOT_STICKY;
    }

    try
    {
      int type = 0;
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
        type = ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
      ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), type);
      mForeground = true;
    }
    catch (Exception e)
    {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && e instanceof ForegroundServiceStartNotAllowedException)
        Logger.e(TAG, "Not in a valid state to start a foreground service", e);
      else
        Logger.e(TAG, "Failed to promote the service to foreground", e);
      // Without the service, the share would run unseen.
      LiveLocation.stopSharing();
      stopSelf();
      return START_NOT_STICKY;
    }

    final LocationHelper locationHelper = MwmApplication.from(this).getLocationHelper();
    locationHelper.addListener(this); // idempotent
    locationHelper.restartWithNewMode(); // starts location if the map had it off
    return START_NOT_STICKY; // after the process dies, the user decides whether to resume (§8.5)
  }

  @Override
  public void onDestroy()
  {
    sRunning = false;
    LiveLocation.removeListener(this);
    unregisterReceiver(mBatteryReceiver);
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
      unregisterReceiver(mBlockedReceiver);
    final LocationHelper locationHelper = MwmApplication.from(this).getLocationHelper();
    locationHelper.removeListener(this);
    if (locationHelper.hasSharingPace())
      locationHelper.stopSharingPace(); // the share alone kept location running in the background
    super.onDestroy();
  }

  // LocationListener

  @Override
  public void onLocationUpdated(@NonNull Location location)
  {
    // Checked before the core may publish.
    if (checkNotifications())
      LiveLocation.onLocation(location);
  }

  // LiveLocation.Listener

  @Override
  public void onSharing(@NonNull Sharing sharing)
  {
    if (!sharing.active)
    {
      Logger.i(TAG, "The share ended");
      stopSelf();
      return;
    }
    updateNotification();
  }

  @Override
  public void onContacts(@NonNull List<Contact> contacts)
  {
    if (LiveLocation.getSharing().active)
      updateNotification();
  }

  @Override
  public void onLocationMode(@NonNull LocationMode mode)
  {
    if (mode != LocationMode.Off && MwmApplication.from(this).getLocationHelper().hasSharingPace())
      useSharingPace(this);
  }

  /** False after stopping the share, when its notification cannot be seen. */
  private boolean checkNotifications()
  {
    if (canNotify(this))
      return true;
    Logger.w(TAG, "The sharing notification cannot be seen: the share stops");
    LiveLocationFeature.onStoppedUnseen();
    LiveLocation.stopSharing();
    return false;
  }

  private void updateNotification()
  {
    if (!canNotify(this))
      return;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        && ContextCompat.checkSelfPermission(this, POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
      return;
    NotificationManagerCompat.from(this).notify(NOTIFICATION_ID, buildNotification());
  }

  @NonNull
  private android.app.Notification buildNotification()
  {
    final int immutable = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0;
    final PendingIntent open = PendingIntent.getActivity(this, 0, LiveLocationActivity.manageIntent(this),
                                                         PendingIntent.FLAG_UPDATE_CURRENT | immutable);
    final PendingIntent stop =
        PendingIntent.getService(this, 1, new Intent(this, LiveLocationService.class).setAction(ACTION_STOP),
                                 PendingIntent.FLAG_UPDATE_CURRENT | immutable);
    final PendingIntent repost =
        PendingIntent.getService(this, 2, new Intent(this, LiveLocationService.class).setAction(ACTION_REPOST),
                                 PendingIntent.FLAG_UPDATE_CURRENT | immutable);

    final String title = getString(R.string.live_location_notification_title);
    // On the lock screen, without the names.
    final android.app.Notification lockScreen = new NotificationCompat.Builder(this, CHANNEL_ID)
                                                    .setSmallIcon(R.drawable.ic_logo_small)
                                                    .setContentTitle(title)
                                                    .setColor(ContextCompat.getColor(this, R.color.notification))
                                                    .build();
    return new NotificationCompat.Builder(this, CHANNEL_ID)
        .setCategory(NotificationCompat.CATEGORY_LOCATION_SHARING)
        .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
        .setPublicVersion(lockScreen)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setShowWhen(false)
        .setSmallIcon(R.drawable.ic_logo_small)
        .setContentTitle(title)
        .setContentText(describeSharing())
        .setContentIntent(open)
        .setDeleteIntent(repost)
        .addAction(0, getString(R.string.live_location_stop), stop)
        .setColor(ContextCompat.getColor(this, R.color.notification))
        .build();
  }

  /** "With Bob and Carol · until 18:30". */
  @NonNull
  private String describeSharing()
  {
    final List<Recipient> recipients = LiveLocation.getSharing().recipients;
    final String with = getString(R.string.live_location_notification_with,
                                  LiveLocationText.joinNames(this, LiveLocationText.namesOf(recipients)));
    final long until = LiveLocationText.latestUntil(recipients);
    if (until == 0)
      return with;
    return getString(R.string.live_location_notification_with_until, with, LiveLocationText.time(this, until));
  }
}
