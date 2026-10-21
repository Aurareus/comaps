package app.organicmaps.sdk.livelocation;

import android.content.Context;
import android.location.Location;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.ChecksSdkIntAtLeast;
import androidx.annotation.Keep;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.WorkerThread;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Consent;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.LocationMode;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.log.Logger;
import java.io.File;
import java.util.ArrayList;
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
    /** The user tapped a contact's dot on the map (docs/LIVE_LOCATION.md §11.4). */
    default void onDotTapped(@NonNull String contactId) {}
  }

  private static final Handler sMain = new Handler(Looper.getMainLooper());
  private static final List<Listener> sListeners = new CopyOnWriteArrayList<>();
  private static boolean sRunning;
  private static boolean sForeground;
  @NonNull
  private static List<Contact> sContacts = Collections.emptyList();
  @NonNull
  private static List<Position> sPositions = Collections.emptyList();
  @NonNull
  private static Sharing sSharing = Sharing.NONE;
  @NonNull
  private static LocationMode sLocationMode = LocationMode.Off;
  private static final Map<String, Pairing> sPairings = new LinkedHashMap<>();

  private LiveLocation() {}

  /** The feature needs Android 7 (docs/LIVE_LOCATION.md §10.1, D6). */
  @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.N)
  public static boolean isSupported()
  {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.N;
  }

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
    final boolean started = nativeStart(storeFile(context).getAbsolutePath());
    nativeSetForeground(sForeground);
    return started;
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

  /**
   * "Delete all live location data": contacts, keys, settings. While the feature is off, without
   * starting anything: the file and the Keystore keys go.
   */
  @MainThread
  public static void deleteAllData(@NonNull Context context)
  {
    if (sRunning)
    {
      nativeDeleteAllData();
      return;
    }
    final File file = storeFile(context);
    if (!file.delete() && file.exists())
      Logger.e(TAG, "Cannot delete " + file);
    // noinspection ResultOfMethodCallIgnored
    new File(file.getPath() + ".tmp").delete();
    if (isSupported())
      KeystoreKeyWrapper.deleteAllExcept("");
  }

  /**
   * Decision D16: about once a day, from a background job, the channel keys that are due are erased
   * and the store's keys rotated, as the core's clock does while it runs. Nothing connects, and
   * nothing happens while the core runs. Waits for the core's thread.
   */
  @WorkerThread
  public static void ratchet(@NonNull Context context)
  {
    if (isSupported())
      nativeRatchet(storeFile(context).getAbsolutePath());
  }

  // The store: one file, in a directory that is not backed up (docs/LIVE_LOCATION.md §8.5).
  @NonNull
  private static File storeFile(@NonNull Context context)
  {
    return new File(context.getNoBackupFilesDir(), "live_location.dat");
  }

  /** The app is in the foreground: contacts' positions are wanted (D11). Kept for a later start. */
  @MainThread
  public static void setForeground(boolean foreground)
  {
    sForeground = foreground;
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

  /** The user's answer about a relay (relay consent). Allowing and refusing are kept until revoked. */
  public static void setConsent(@NonNull String url, @NonNull Consent consent, @NonNull String forContact)
  {
    if (sRunning)
      nativeSetConsent(url, consent.ordinal(), forContact);
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

  /** The dot colour contacts see: a name from {@link Settings#dotColors}, or "" to let each of them pick. */
  public static boolean setColor(@NonNull String color)
  {
    return sRunning && nativeSetColor(color);
  }

  /** Sharing stops at this battery level, 0 to 50 percent; 0: never. */
  public static boolean setLowBatteryStop(int percent)
  {
    return sRunning && nativeSetLowBatteryStop(percent);
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

  /** The pairings this run has heard of, the ones that ended too. */
  @NonNull
  public static List<Pairing> getPairings()
  {
    return new ArrayList<>(sPairings.values());
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

  /** Another end for a current recipient's share, earlier or later (0: until stopped). Same stream. */
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

  /** A fix from the location provider. The core drops a fix without accuracy, and values out of range. */
  public static void onLocation(@NonNull Location location)
  {
    if (!sRunning)
      return;
    nativeOnLocation(location.getLatitude(), location.getLongitude(),
                     location.hasAccuracy() ? location.getAccuracy() : -1,
                     location.hasSpeed() ? location.getSpeed() : -1, location.hasBearing() ? location.getBearing() : -1,
                     location.hasAltitude(), location.getAltitude(), location.getTime());
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

  // Called from JNI on the map's GUI thread.
  @Keep
  @SuppressWarnings("unused")
  private static void onDotTapped(@NonNull String contactId)
  {
    sMain.post(() -> {
      if (sRunning)
        for (Listener listener : sListeners)
          listener.onDotTapped(contactId);
    });
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

  private static native boolean nativeStart(@NonNull String path);
  private static native void nativeRatchet(@NonNull String path);
  private static native void nativeStop();
  private static native void nativeDeleteAllData();
  private static native void nativeSetForeground(boolean foreground);
  @NonNull
  private static native String nativeGetSettings();
  private static native boolean nativeSetName(@NonNull String name);
  private static native boolean nativeSetHomeRelays(@NonNull String[] relays);
  private static native void nativeSetConsent(@NonNull String url, int consent, @NonNull String forContact);
  private static native void nativeRevokeConsent(@NonNull String url);
  private static native void nativeSetRequestLive(boolean request);
  private static native void nativeSetAllowLive(boolean allow);
  private static native boolean nativeSetColor(@NonNull String color);
  private static native boolean nativeSetLowBatteryStop(int percent);
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
  // Unknown accuracy, speed and bearing are negative: no NaN crosses JNI (the native side is built with
  // -ffast-math).
  private static native void nativeOnLocation(double lat, double lon, double accuracy, double speed, double bearing,
                                              boolean hasAltitude, double altitude, long timeMs);
  private static native void nativeOnBatteryLevel(int percent);
}
