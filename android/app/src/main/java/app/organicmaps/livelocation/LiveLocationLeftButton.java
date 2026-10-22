package app.organicmaps.livelocation;

import android.content.Context;
import androidx.annotation.NonNull;
import app.organicmaps.R;
import app.organicmaps.leftbutton.LeftButton;
import app.organicmaps.sdk.livelocation.LiveLocation;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/**
 * Live location (NLL): "Share Live Location", one of the actions Settings → Interface → Left button setup
 * offers for the map's left button (docs/LIVE_LOCATION.md §11.3). It opens Manage sharing, where the user
 * picks whom to share with, as the sharing indicator does; with no contacts yet, "Share My Location",
 * where they add one; with the feature off, its explanation, where they turn it on.
 */
public final class LiveLocationLeftButton implements LeftButton
{
  public static final String CODE = "live-location";

  @NonNull
  private final String mName;

  public LiveLocationLeftButton(@NonNull Context context)
  {
    mName = context.getString(R.string.live_location_left_button);
  }

  @Override
  public String getCode()
  {
    return CODE;
  }

  @Override
  public String getPrefsName()
  {
    return mName;
  }

  @Override
  public void drawIcon(FloatingActionButton imageView)
  {
    imageView.setImageResource(R.drawable.ic_live_location_settings);
  }

  @Override
  public void onClick(FloatingActionButton leftButtonView)
  {
    final Context context = leftButtonView.getContext();
    if (LiveLocationFeature.isEnabled(context) && !LiveLocation.getContacts().isEmpty())
      context.startActivity(LiveLocationActivity.manageIntent(context));
    else
      context.startActivity(LiveLocationActivity.contactsIntent(context));
  }
}
