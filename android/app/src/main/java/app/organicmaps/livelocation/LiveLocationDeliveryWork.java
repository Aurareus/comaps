package app.organicmaps.livelocation;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import app.organicmaps.sdk.livelocation.LiveLocation;
import java.util.concurrent.TimeUnit;

/**
 * Live location (NLL): what no relay has accepted yet goes out once there is a network, also after the app
 * was closed or the phone restarted (docs/LIVE_LOCATION.md §29, §30). E.g. a share stopped in a tunnel,
 * which contacts would otherwise see running until the user opens the app again; a deleted contact's end; a
 * share's end told once more on the next day. It runs the core for that if it does not run, which then
 * goes again. Only while the app is neither on screen nor sharing (LiveLocationFeature); and while the
 * feature is off, for a week after it was turned off: turning it off stops any share, and contacts are told.
 */
public class LiveLocationDeliveryWork extends Worker
{
  private static final String NAME = "LiveLocationDelivery";

  public LiveLocationDeliveryWork(@NonNull Context context, @NonNull WorkerParameters params)
  {
    super(context, params);
  }

  /**
   * Something is due at {@code at} (Unix seconds; at or before now: once there is a network), 0: nothing. It
   * takes the place of the job there was, also of a run in progress, which then schedules nothing.
   */
  static void schedule(@NonNull Context context, long at)
  {
    final WorkManager manager = WorkManager.getInstance(context);
    if (at == 0)
      manager.cancelUniqueWork(NAME);
    else
      manager.enqueueUniqueWork(NAME, ExistingWorkPolicy.REPLACE, request(at));
  }

  @NonNull
  private static OneTimeWorkRequest request(long at)
  {
    final long delayMs = Math.max(0, at * 1000 - System.currentTimeMillis());
    return new OneTimeWorkRequest.Builder(LiveLocationDeliveryWork.class)
        .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
        .setInitialDelay(delayMs, TimeUnit.MILLISECONDS)
        .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
        .build();
  }

  @NonNull
  @Override
  public Result doWork()
  {
    if (!LiveLocationFeature.mayDeliver(getApplicationContext()))
      return Result.success(); // turned off over a week ago: what is still unsent stays so
    final long due = LiveLocation.deliver(getApplicationContext());
    // Stopped: the app's core said meanwhile what is due, or came on screen and sends by itself.
    if (due == 0 || isStopped())
      return Result.success();
    // Not accepted yet, e.g. the relays are down: again later, backing off.
    if (due * 1000 <= System.currentTimeMillis())
      return Result.retry();
    // Due later, e.g. a share's end once more on the next day: the next run, once this one has ended.
    WorkManager.getInstance(getApplicationContext())
        .enqueueUniqueWork(NAME, ExistingWorkPolicy.APPEND_OR_REPLACE, request(due));
    return Result.success();
  }
}
