package app.organicmaps.sdk.livelocation;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.Keep;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.LocationMode;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.log.Logger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Live location (NLL): the app's side of the native core (docs/LIVE_LOCATION.md §8). Everything here
 * is called on the main thread; the core runs on a thread of its own, and its events come back here
 * on the main thread. Positions stay in memory; keys never reach Java.
 */
public final class LiveLocation
{
  private static final String TAG = LiveLocation.class.getSimpleName();

  public interface Listener
  {
    default void onContacts(@NonNull List<Contact> contacts) {}
    default void onPairing(@NonNull Pairing pairing) {}
    default void onPositions(@NonNull List<Position> positions) {}
    default void onSharing(@NonNull Sharing sharing) {}
    default void onConsentNeeded(@NonNull ConsentRequest request) {}
    default void onLocationMode(@NonNull LocationMode mode) {}
    /** The store could not be read or written: offer to delete the live location data. */
    default void onStoreError() {}
  }

  private static final Handler sMain = new Handler(Looper.getMainLooper());
  private static final List<Listener> sListeners = new CopyOnWriteArrayList<>();
  private static boolean sRunning;
  @NonNull private static List<Contact> sContacts = Collections.emptyList();
  @NonNull private static List<Position> sPositions = Collections.emptyList();
  @NonNull private static Sharing sSharing = Sharing.NONE;
  @NonNull private static LocationMode sLocationMode = LocationMode.Off;
  private static final Map<String, Pairing> sPairings = new LinkedHashMap<>();

  private LiveLocation() {}

  public static boolean isRunning()
  {
    return sRunning;
  }

  /**
   * The feature is on: starts the core (its thread, its store). False when the store exists but
   * cannot be read; {@link #deleteAllData()} then starts afresh.
   */
  @MainThread
  public static boolean start(@NonNull Context context)
  {
    if (sRunning)
      return true;
    sRunning = true;
    return nativeStart(context.getNoBackupFilesDir().getAbsolutePath());
  }

  /** The feature is off: stops any share, closes every connection and frees the core. The data stays. */
  @MainThread
  public static void stop()
  {
    if (!sRunning)
      return;
    nativeStop();
    sRunning = false;
    sContacts = Collections.emptyList();
    sPositions = Collections.emptyList();
    sSharing = Sharing.NONE;
    sLocationMode = LocationMode.Off;
    sPairings.clear();
  }

  @MainThread
  public static void deleteAllData()
  {
    if (sRunning)
      nativeDeleteAllData();
  }

  /** The map is visible: contacts' positions are wanted (D11). */
  @MainThread
  public static void setForeground(boolean foreground)
  {
    if (sRunning)
      nativeSetForeground(foreground);
  }

  // --- Settings ---------------------------------------------------------------------------------

  @Nullable
  public static Settings getSettings()
  {
    if (!sRunning)
      return null;
    try
    {
      return new Settings(new JSONObject(nativeGetSettings()));
    }
    catch (JSONException e)
    {
      Logger.e(TAG, "Settings", e);
      return null;
    }
  }

  public static boolean setName(@NonNull String name)
  {
    return sRunning && nativeSetName(name);
  }

  public static boolean setHomeRelays(@NonNull List<String> relays)
  {
    return sRunning && nativeSetHomeRelays(relays.toArray(new String[0]));
  }

  /** The user's answer about a relay (relay consent): kept until revoked. */
  public static void setConsent(@NonNull String url, boolean allowed, @NonNull String forContact)
  {
    if (sRunning)
      nativeSetConsent(url, allowed, forContact);
  }

  public static void revokeConsent(@NonNull String url)
  {
    if (sRunning)
      nativeRevokeConsent(url);
  }

  public static void setRequestLive(boolean request)
  {
    if (sRunning)
      nativeSetRequestLive(request);
  }

  public static void setAllowLive(boolean allow)
  {
    if (sRunning)
      nativeSetAllowLive(allow);
  }

  // --- Pairing ----------------------------------------------------------------------------------

  /** A QR code lives 10 minutes, a link a day. Null without a name. */
  @Nullable
  public static Pairing createInvite(boolean byLink)
  {
    return sRunning ? pairing(nativeCreateInvite(byLink)) : null;
  }

  /** Null for an invalid link. The result may ask for relays first (NeedsConsent): ask, then call again. */
  @Nullable
  public static Pairing openInvite(@NonNull String link)
  {
    return sRunning ? pairing(nativeOpenInvite(link)) : null;
  }

  public static void confirmCode(@NonNull String pairingId, boolean match)
  {
    if (sRunning)
      nativeConfirmCode(pairingId, match);
  }

  public static void decide(@NonNull String pairingId, boolean accept, boolean compared)
  {
    if (sRunning)
      nativeDecide(pairingId, accept, compared);
  }

  public static void cancelPairing(@NonNull String pairingId)
  {
    if (sRunning)
      nativeCancelPairing(pairingId);
  }

  @Nullable
  public static Pairing getPairing(@NonNull String pairingId)
  {
    return sPairings.get(pairingId);
  }

  // --- Contacts ---------------------------------------------------------------------------------

  @NonNull
  public static List<Contact> getContacts()
  {
    return sContacts;
  }

  @Nullable
  public static Contact getContact(@NonNull String id)
  {
    for (Contact contact : sContacts)
      if (contact.id.equals(id))
        return contact;
    return null;
  }

  public static void renameContact(@NonNull String id, @NonNull String name)
  {
    if (sRunning)
      nativeRenameContact(id, name);
  }

  public static void deleteContact(@NonNull String id)
  {
    if (sRunning)
      nativeDeleteContact(id);
  }

  public static void markVerified(@NonNull String id)
  {
    if (sRunning)
      nativeMarkVerified(id);
  }

  public static void setHidden(@NonNull String id, boolean hidden)
  {
    if (sRunning)
      nativeSetHidden(id, hidden);
  }

  // --- Sharing ----------------------------------------------------------------------------------

  @NonNull
  public static Sharing getSharing()
  {
    return sSharing;
  }

  @NonNull
  public static LocationMode getLocationMode()
  {
    return sLocationMode;
  }

  @NonNull
  public static List<Position> getPositions()
  {
    return sPositions;
  }

  /** False if a recipient is unknown or flagged, or a time limit is in the past. */
  public static boolean startSharing(@NonNull List<Recipient> recipients)
  {
    return sRunning && nativeStartSharing(ids(recipients), untils(recipients));
  }

  /** A new set of recipients; empty stops sharing. */
  public static boolean changeSharing(@NonNull List<Recipient> recipients)
  {
    return sRunning && nativeChangeSharing(ids(recipients), untils(recipients));
  }

  public static boolean extendSharing(@NonNull String id, long until)
  {
    return sRunning && nativeExtendSharing(id, until);
  }

  public static void stopSharing()
  {
    if (sRunning)
      nativeStopSharing();
  }

  public static void dismissResume()
  {
    if (sRunning)
      nativeDismissResume();
  }

  /** A fix from the location provider. NaN for what it does not know. */
  public static void onLocation(double lat, double lon, double accuracy, double speed, double bearing, double altitude,
                                long timeMs)
  {
    if (sRunning)
      nativeOnLocation(lat, lon, accuracy, speed, bearing, altitude, timeMs);
  }

  public static void onBatteryLevel(int percent)
  {
    if (sRunning)
      nativeOnBatteryLevel(percent);
  }

  // --- Events -----------------------------------------------------------------------------------

  @MainThread
  public static void addListener(@NonNull Listener listener)
  {
    sListeners.add(listener);
  }

  @MainThread
  public static void removeListener(@NonNull Listener listener)
  {
    sListeners.remove(listener);
  }

  // Called from JNI on the live location thread.
  @Keep
  @SuppressWarnings("unused")
  private static void onEvent(@NonNull String json)
  {
    sMain.post(() -> dispatch(json));
  }

  @MainThread
  private static void dispatch(@NonNull String json)
  {
    if (!sRunning)
      return;
    try
    {
      final JSONObject event = new JSONObject(json);
      switch (event.optString("event"))
      {
      case "contacts":
        sContacts = Contact.list(event);
        for (Listener listener : sListeners)
          listener.onContacts(sContacts);
        break;
      case "pairing":
        final Pairing p = new Pairing(event);
        sPairings.put(p.id, p);
        for (Listener listener : sListeners)
          listener.onPairing(p);
        break;
      case "positions":
        sPositions = Position.list(event);
        for (Listener listener : sListeners)
          listener.onPositions(sPositions);
        break;
      case "sharing":
        sSharing = new Sharing(event);
        for (Listener listener : sListeners)
          listener.onSharing(sSharing);
        break;
      case "consent":
        final ConsentRequest request = new ConsentRequest(event);
        for (Listener listener : sListeners)
          listener.onConsentNeeded(request);
        break;
      case "location":
        sLocationMode = LocationMode.valueOf(event.optString("mode", "Off"));
        for (Listener listener : sListeners)
          listener.onLocationMode(sLocationMode);
        break;
      case "store_error":
        for (Listener listener : sListeners)
          listener.onStoreError();
        break;
      default: Logger.w(TAG, "Unknown event " + event.optString("event"));
      }
    }
    catch (JSONException | IllegalArgumentException e)
    {
      Logger.e(TAG, "Bad event", e);
    }
  }

  @Nullable
  private static Pairing pairing(@Nullable String json)
  {
    if (json == null)
      return null;
    try
    {
      final Pairing p = new Pairing(new JSONObject(json));
      if (!p.id.isEmpty())
        sPairings.put(p.id, p);
      return p;
    }
    catch (JSONException e)
    {
      Logger.e(TAG, "Pairing", e);
      return null;
    }
  }

  @NonNull
  private static String[] ids(@NonNull List<Recipient> recipients)
  {
    final String[] out = new String[recipients.size()];
    for (int i = 0; i < out.length; ++i)
      out[i] = recipients.get(i).contactId;
    return out;
  }

  @NonNull
  private static long[] untils(@NonNull List<Recipient> recipients)
  {
    final long[] out = new long[recipients.size()];
    for (int i = 0; i < out.length; ++i)
      out[i] = recipients.get(i).until;
    return out;
  }

  private static native boolean nativeStart(@NonNull String directory);
  private static native void nativeStop();
  private static native void nativeDeleteAllData();
  private static native void nativeSetForeground(boolean foreground);
  @NonNull
  private static native String nativeGetSettings();
  private static native boolean nativeSetName(@NonNull String name);
  private static native boolean nativeSetHomeRelays(@NonNull String[] relays);
  private static native void nativeSetConsent(@NonNull String url, boolean allowed, @NonNull String forContact);
  private static native void nativeRevokeConsent(@NonNull String url);
  private static native void nativeSetRequestLive(boolean request);
  private static native void nativeSetAllowLive(boolean allow);
  @Nullable
  private static native String nativeCreateInvite(boolean byLink);
  @Nullable
  private static native String nativeOpenInvite(@NonNull String link);
  private static native void nativeConfirmCode(@NonNull String pairingId, boolean match);
  private static native void nativeDecide(@NonNull String pairingId, boolean accept, boolean compared);
  private static native void nativeCancelPairing(@NonNull String pairingId);
  private static native void nativeRenameContact(@NonNull String id, @NonNull String name);
  private static native void nativeDeleteContact(@NonNull String id);
  private static native void nativeMarkVerified(@NonNull String id);
  private static native void nativeSetHidden(@NonNull String id, boolean hidden);
  private static native boolean nativeStartSharing(@NonNull String[] ids, @NonNull long[] untils);
  private static native boolean nativeChangeSharing(@NonNull String[] ids, @NonNull long[] untils);
  private static native boolean nativeExtendSharing(@NonNull String id, long until);
  private static native void nativeStopSharing();
  private static native void nativeDismissResume();
  private static native void nativeOnLocation(double lat, double lon, double accuracy, double speed, double bearing,
                                              double altitude, long timeMs);
  private static native void nativeOnBatteryLevel(int percent);
}
