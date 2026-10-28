package app.organicmaps.livelocation;

import android.content.Intent;
import android.net.Uri;
import androidx.annotation.NonNull;
import app.organicmaps.MwmActivity;
import app.organicmaps.R;
import app.organicmaps.intent.IntentProcessor;
import app.organicmaps.sdk.livelocation.LiveLocation;

/**
 * Live location (NLL): an invite link, comaps://live/pair#… (docs/LIVE_LOCATION_PROTOCOL.md §6.1),
 * opens the pairing screen. It goes before the handler of comaps:// short links, which it cannot be:
 * "/" and "#" are outside their alphabet. Below Android 7, which the feature needs, the map says so:
 * whoever sent the link expects it to do something.
 */
public class LiveLocationInviteProcessor implements IntentProcessor
{
  @Override
  public boolean process(@NonNull Intent intent, @NonNull MwmActivity activity)
  {
    final Uri uri = intent.getData();
    if (uri == null || !isInvite(uri))
      return false;
    if (!LiveLocation.isSupported())
    {
      LiveLocationDialogs.showMessage(activity, null, activity.getString(R.string.live_location_needs_android_7));
      return true;
    }
    activity.startActivity(LiveLocationActivity.joinIntent(activity, uri.toString()));
    return true;
  }

  static boolean isInvite(@NonNull Uri uri)
  {
    return "comaps".equals(uri.getScheme()) && "live".equals(uri.getHost()) && "/pair".equals(uri.getPath());
  }
}
