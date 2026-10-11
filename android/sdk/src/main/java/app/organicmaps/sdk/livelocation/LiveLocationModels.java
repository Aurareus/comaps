package app.organicmaps.sdk.livelocation;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Live location (NLL): the native core's views, parsed from its JSON events. */
public final class LiveLocationModels
{
  private LiveLocationModels() {}

  @Nullable
  private static Long optionalLong(@NonNull JSONObject json, @NonNull String name)
  {
    return json.isNull(name) ? null : json.optLong(name);
  }

  @NonNull
  private static List<String> strings(@Nullable JSONArray array)
  {
    final List<String> out = new ArrayList<>();
    if (array != null)
      for (int i = 0; i < array.length(); ++i)
        out.add(array.optString(i));
    return Collections.unmodifiableList(out);
  }

  public static final class Contact
  {
    @NonNull public final String id;
    @NonNull public final String name;
    @NonNull public final String sas;
    public final boolean verified;
    public final boolean flagged;
    /** The joiner has not confirmed yet (D18). */
    public final boolean waiting;
    /** ... and the week of confirmations is over: offer to remove the contact. */
    public final boolean offerRemoval;
    public final boolean hidden;
    /** Seconds since the epoch, 0 until stopped; null when the contact does not share with this user. */
    @Nullable public final Long sharesWithMeUntil;
    /** The same for this user's share with the contact. */
    @Nullable public final Long iShareUntil;
    /** Live updates need a relay this user has not allowed. */
    public final boolean liveUpdatesOff;

    Contact(@NonNull JSONObject json)
    {
      id = json.optString("id");
      name = json.optString("name");
      sas = json.optString("sas");
      verified = json.optBoolean("verified");
      flagged = json.optBoolean("flagged");
      waiting = json.optBoolean("waiting");
      offerRemoval = json.optBoolean("offer_removal");
      hidden = json.optBoolean("hidden");
      sharesWithMeUntil = optionalLong(json, "shares_with_me");
      iShareUntil = optionalLong(json, "i_share");
      liveUpdatesOff = json.optBoolean("live_updates_off");
    }

    @NonNull
    static List<Contact> list(@NonNull JSONObject event) throws JSONException
    {
      final JSONArray array = event.getJSONArray("contacts");
      final List<Contact> out = new ArrayList<>();
      for (int i = 0; i < array.length(); ++i)
        out.add(new Contact(array.getJSONObject(i)));
      return Collections.unmodifiableList(out);
    }
  }

  public static final class Pairing
  {
    public enum Stage
    {
      NeedsConsent,
      Waiting,
      CompareCode,
      Connected,
      Declined,
      Cancelled,
      Conflict,
      Expired
    }

    @NonNull public final String id;
    public final boolean inviter;
    @NonNull public final Stage stage;
    /** The inviter's invite link while it waits; empty otherwise. */
    @NonNull public final String link;
    public final long expiresAt;
    @NonNull public final String sas;
    @NonNull public final String peerName;
    @NonNull public final String contactId;
    /** Relays the user must allow before joining. */
    @NonNull public final List<String> needsConsent;

    Pairing(@NonNull JSONObject json)
    {
      id = json.optString("id");
      inviter = json.optBoolean("inviter");
      Stage parsed;
      try
      {
        parsed = Stage.valueOf(json.optString("stage"));
      }
      catch (IllegalArgumentException e)
      {
        parsed = Stage.Cancelled;
      }
      stage = parsed;
      link = json.optString("link");
      expiresAt = json.optLong("expires");
      sas = json.optString("sas");
      peerName = json.optString("peer");
      contactId = json.optString("contact");
      needsConsent = strings(json.optJSONArray("consent"));
    }
  }

  public static final class Position
  {
    @NonNull public final String contactId;
    @NonNull public final String name;
    public final double lat;
    public final double lon;
    public final double accuracy;
    /** The fix time, in milliseconds since the epoch. */
    public final long timeMs;
    /** Over two minutes old, or its stream ended. */
    public final boolean stale;

    Position(@NonNull JSONObject json)
    {
      contactId = json.optString("id");
      name = json.optString("name");
      lat = json.optDouble("lat");
      lon = json.optDouble("lon");
      accuracy = json.optDouble("acc");
      timeMs = json.optLong("ts");
      stale = json.optBoolean("stale");
    }

    @NonNull
    static List<Position> list(@NonNull JSONObject event) throws JSONException
    {
      final JSONArray array = event.getJSONArray("positions");
      final List<Position> out = new ArrayList<>();
      for (int i = 0; i < array.length(); ++i)
        out.add(new Position(array.getJSONObject(i)));
      return Collections.unmodifiableList(out);
    }
  }

  /** A recipient of a share: a contact id and the share's end (seconds since the epoch, 0: until stopped). */
  public static final class Recipient
  {
    @NonNull public final String contactId;
    public final long until;

    public Recipient(@NonNull String contactId, long until)
    {
      this.contactId = contactId;
      this.until = until;
    }

    @NonNull
    static List<Recipient> list(@Nullable JSONArray array) throws JSONException
    {
      final List<Recipient> out = new ArrayList<>();
      if (array != null)
        for (int i = 0; i < array.length(); ++i)
          out.add(new Recipient(array.getJSONObject(i).optString("id"), array.getJSONObject(i).optLong("until")));
      return Collections.unmodifiableList(out);
    }
  }

  public static final class Sharing
  {
    public final boolean active;
    /** A viewer asked for live updates. */
    public final boolean live;
    @NonNull public final List<Recipient> recipients;
    /** What the user may resume after the app's process died while sharing. */
    @NonNull public final List<Recipient> resumable;

    Sharing(@NonNull JSONObject json) throws JSONException
    {
      active = json.optBoolean("active");
      live = json.optBoolean("live");
      recipients = Recipient.list(json.optJSONArray("recipients"));
      resumable = Recipient.list(json.optJSONArray("resumable"));
    }

    static final Sharing NONE = new Sharing();

    private Sharing()
    {
      active = false;
      live = false;
      recipients = Collections.emptyList();
      resumable = Collections.emptyList();
    }
  }

  public static final class ConsentRequest
  {
    public enum Purpose
    {
      Pairing,
      Viewing,
      LiveUpdates,
      Sending
    }

    @NonNull public final String url;
    /** Empty for a pairing: the inviter's name is not known yet. */
    @NonNull public final String contactName;
    @NonNull public final Purpose purpose;

    ConsentRequest(@NonNull JSONObject json)
    {
      url = json.optString("url");
      contactName = json.optString("contact");
      switch (json.optString("purpose"))
      {
      case "pairing": purpose = Purpose.Pairing; break;
      case "live_updates": purpose = Purpose.LiveUpdates; break;
      case "sending": purpose = Purpose.Sending; break;
      default: purpose = Purpose.Viewing; break;
      }
    }
  }

  /** What the location provider should deliver (docs/LIVE_LOCATION.md §10.3). */
  public enum LocationMode
  {
    Off,
    Idle,
    Live
  }

  public static final class Settings
  {
    @NonNull public final String name;
    @NonNull public final List<String> homeRelays;
    /** Relays approved under relay consent, with the contact each was approved for. */
    @NonNull public final List<String[]> approved;
    @NonNull public final List<String> declined;
    public final boolean requestLive;
    public final boolean allowLive;
    public final int lowBatteryStop;

    Settings(@NonNull JSONObject json) throws JSONException
    {
      name = json.optString("name");
      homeRelays = strings(json.optJSONArray("relays"));
      final List<String[]> list = new ArrayList<>();
      final JSONArray array = json.optJSONArray("approved");
      if (array != null)
        for (int i = 0; i < array.length(); ++i)
          list.add(new String[] {array.getJSONObject(i).optString("url"), array.getJSONObject(i).optString("contact")});
      approved = Collections.unmodifiableList(list);
      declined = strings(json.optJSONArray("declined"));
      requestLive = json.optBoolean("request_live", true);
      allowLive = json.optBoolean("allow_live", true);
      lowBatteryStop = json.optInt("low_battery_stop", 5);
    }
  }
}
