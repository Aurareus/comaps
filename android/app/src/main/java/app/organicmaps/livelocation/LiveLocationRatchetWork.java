package app.organicmaps.livelocation;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import app.organicmaps.sdk.livelocation.LiveLocation;
import java.util.concurrent.TimeUnit;

/**
 * Live location (NLL): decision D16. About once a day while the feature is on, even when the app is
 * not used, the channel keys that are due are erased and the store's keys rotated, so that a phone
 * taken from its owner holds no older keys than about a day's (docs/LIVE_LOCATION.md, threat T7).
 * It sends nothing. "About": Android defers the jobs of rarely used apps.
 */
public class LiveLocationRatchetWork extends Worker
{
  private static final String NAME = "LiveLocationRatchet";

  public LiveLocationRatchetWork(@NonNull Context context, @NonNull WorkerParameters params)
  {
    super(context, params);
  }

  static void schedule(@NonNull Context context)
  {
    final PeriodicWorkRequest request =
        new PeriodicWorkRequest.Builder(LiveLocationRatchetWork.class, 1, TimeUnit.DAYS).build();
    WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, request);
  }

  static void cancel(@NonNull Context context)
  {
    WorkManager.getInstance(context).cancelUniqueWork(NAME);
  }

  @NonNull
  @Override
  public Result doWork()
  {
    final Context context = getApplicationContext();
    if (LiveLocationFeature.isEnabled(context))
      LiveLocation.ratchet(context);
    return Result.success();
  }
}
