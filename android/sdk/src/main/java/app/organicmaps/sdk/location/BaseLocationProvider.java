package app.organicmaps.sdk.location;

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;
import static android.Manifest.permission.ACCESS_FINE_LOCATION;

import android.app.PendingIntent;
import android.location.Location;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresPermission;
import androidx.annotation.UiThread;

public abstract class BaseLocationProvider
{
  public interface Listener
  {
    @UiThread
    void onLocationChanged(@NonNull Location location);
    @UiThread
    void onLocationDisabled();
    // Used by GoogleFusedLocationProvider.
    @SuppressWarnings("unused")
    @UiThread
    void onLocationResolutionRequired(@NonNull PendingIntent pendingIntent);
    // Used by GoogleFusedLocationProvider.
    @SuppressWarnings("unused")
    @UiThread
    void onFusedLocationUnsupported();
  }

  @NonNull
  protected final Listener mListener;
  // Live location (NLL): a share alone in the background asks for balanced accuracy when idle
  // (docs/LIVE_LOCATION.md §10.3). Applies from the next start().
  protected boolean mBalancedPower;

  protected BaseLocationProvider(@NonNull Listener listener)
  {
    mListener = listener;
  }

  void setBalancedPower(boolean balanced)
  {
    mBalancedPower = balanced;
  }

  @RequiresPermission(anyOf = {ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION})
  protected abstract void start(long interval);
  protected abstract void stop();
}
