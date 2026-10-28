package app.organicmaps.livelocation;

import android.content.Context;
import androidx.annotation.NonNull;
import app.organicmaps.R;

/**
 * Live location (NLL): how long a share lasts, as picked under "For": a length of time from when it
 * starts, until the user stops it, or until a time of day.
 */
final class ShareDuration
{
  static final ShareDuration UNTIL_STOPPED = new ShareDuration(0, 0);
  /** The lengths offered, then "Until I stop"; "Until…" picks a time. */
  static final ShareDuration[] CHOICES = {new ShareDuration(15 * 60, 0), new ShareDuration(60 * 60, 0),
                                          new ShareDuration(8 * 60 * 60, 0), UNTIL_STOPPED};
  static final ShareDuration DEFAULT = CHOICES[1];

  /** A length, in seconds; 0 with no `until`: until stopped. */
  final long mSeconds;
  /** An end, in seconds since the epoch, instead of a length; 0: none. */
  final long mUntil;

  ShareDuration(long seconds, long until)
  {
    mSeconds = seconds;
    mUntil = until;
  }

  /** Until `until`, seconds since the epoch. */
  @NonNull
  static ShareDuration endingAt(long until)
  {
    return new ShareDuration(0, until);
  }

  /** The `until` of a share starting at `now`; 0: until stopped. */
  long until(long now)
  {
    if (mUntil != 0)
      return mUntil;
    return mSeconds == 0 ? 0 : now + mSeconds;
  }

  /** The choice to show as picked for a share ending at `until` (0: until stopped). */
  @NonNull
  static ShareDuration of(long until)
  {
    return until == 0 ? UNTIL_STOPPED : endingAt(until);
  }

  /** Its place among {@link #CHOICES}, or -1 for a time of day. */
  int choice()
  {
    for (int i = 0; i < CHOICES.length; ++i)
      if (CHOICES[i].mSeconds == mSeconds && CHOICES[i].mUntil == mUntil)
        return i;
    return -1;
  }

  @NonNull
  String label(@NonNull Context context)
  {
    if (mUntil != 0)
      return context.getString(R.string.live_location_until, LiveLocationText.time(context, mUntil));
    if (mSeconds == 0)
      return context.getString(R.string.live_location_until_stopped);
    if (mSeconds < 60 * 60)
      return context.getString(R.string.live_location_minutes, mSeconds / 60);
    final int hours = (int) (mSeconds / (60 * 60));
    return context.getResources().getQuantityString(R.plurals.live_location_hours, hours, hours);
  }
}
