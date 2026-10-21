package app.organicmaps.livelocation;

import android.content.Context;
import android.text.format.DateFormat;
import android.text.format.DateUtils;
import androidx.annotation.NonNull;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/** Live location (NLL): how names and times read in the live location screens. */
final class LiveLocationText
{
  private LiveLocationText() {}

  /** "Bob", "Bob and Carol", "Bob, Carol and 2 others". */
  @NonNull
  static String joinNames(@NonNull Context context, @NonNull List<String> names)
  {
    if (names.isEmpty())
      return "";
    if (names.size() == 1)
      return names.get(0);
    if (names.size() == 2)
      return context.getString(R.string.live_location_two_names, names.get(0), names.get(1));
    final int others = names.size() - 2;
    return context.getResources().getQuantityString(R.plurals.live_location_more_names, others,
                                                    names.get(0) + ", " + names.get(1), others);
  }

  @NonNull
  static List<String> namesOf(@NonNull List<Recipient> recipients)
  {
    final List<String> names = new ArrayList<>();
    for (Recipient recipient : recipients)
    {
      final Contact contact = LiveLocation.getContact(recipient.contactId);
      names.add(contact != null ? contact.name : "?");
    }
    return names;
  }

  /** The latest end of the recipients' shares, in seconds; 0 when one of them lasts until stopped. */
  static long latestUntil(@NonNull List<Recipient> recipients)
  {
    long until = 0;
    for (Recipient recipient : recipients)
    {
      if (recipient.until == 0)
        return 0;
      until = Math.max(until, recipient.until);
    }
    return until;
  }

  /**
   * A contact's state, one line each: who shares with whom, still connecting, live updates off, not yet
   * moved to the user's new relays, hidden.
   */
  @NonNull
  static String status(@NonNull Context context, @NonNull Contact contact)
  {
    final List<String> lines = new ArrayList<>();
    if (contact.sharesWithMeUntil != null)
      lines.add(contact.sharesWithMeUntil == 0 ? context.getString(R.string.live_location_sharing_with_you)
                                               : context.getString(R.string.live_location_sharing_with_you_until,
                                                                   time(context, contact.sharesWithMeUntil)));
    if (contact.iShareUntil != null)
      lines.add(contact.iShareUntil == 0
                    ? context.getString(R.string.live_location_you_share)
                    : context.getString(R.string.live_location_you_share_until, time(context, contact.iShareUntil)));
    if (contact.waiting)
      lines.add(context.getString(R.string.live_location_waiting_for, contact.name));
    if (contact.liveUpdatesOff)
      lines.add(context.getString(R.string.live_location_live_updates_off));
    if (contact.notMoved)
      lines.add(context.getString(contact.moveOverdue ? R.string.live_location_move_overdue
                                                      : R.string.live_location_not_moved));
    if (contact.hidden)
      lines.add(context.getString(R.string.live_location_hidden));
    return String.join("\n", lines);
  }

  /** A dot colour's name (spec §8), in the words of CoMaps' bookmark colours; "Automatic" for none. */
  @NonNull
  static String colorName(@NonNull Context context, @NonNull String color)
  {
    final int name = switch (color)
    {
      case "red" -> R.string.red;
      case "pink" -> R.string.pink;
      case "purple" -> R.string.purple;
      case "deeppurple" -> R.string.deep_purple;
      case "blue" -> R.string.blue;
      case "lightblue" -> R.string.light_blue;
      case "cyan" -> R.string.cyan;
      case "teal" -> R.string.teal;
      case "green" -> R.string.green;
      case "lime" -> R.string.lime;
      case "yellow" -> R.string.yellow;
      case "orange" -> R.string.orange;
      case "deeporange" -> R.string.deep_orange;
      case "brown" -> R.string.brown;
      default -> R.string.live_location_dot_color_automatic;
    };
    return context.getString(name);
  }

  /** Verified, not verified, or flagged: the codes must be compared (§11.2). */
  @NonNull
  static String badge(@NonNull Context context, @NonNull Contact contact)
  {
    if (contact.flagged)
      return context.getString(R.string.live_location_flagged);
    return context.getString(contact.verified ? R.string.live_location_verified : R.string.live_location_unverified);
  }

  /** "18:30" today, otherwise with the date. */
  @NonNull
  static String time(@NonNull Context context, long unixSeconds)
  {
    final Date date = new Date(unixSeconds * 1000);
    final String time = DateFormat.getTimeFormat(context).format(date);
    final Calendar then = Calendar.getInstance();
    then.setTime(date);
    final Calendar now = Calendar.getInstance();
    if (then.get(Calendar.YEAR) == now.get(Calendar.YEAR)
        && then.get(Calendar.DAY_OF_YEAR) == now.get(Calendar.DAY_OF_YEAR))
      return time;
    return DateFormat.getMediumDateFormat(context).format(date) + " " + time;
  }

  /** "3 min ago". */
  @NonNull
  static String ago(long timeMs)
  {
    return DateUtils
        .getRelativeTimeSpanString(timeMs, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS,
                                   DateUtils.FORMAT_ABBREV_RELATIVE)
        .toString();
  }

  /** "1 h 30 min", for the time an invite has left. */
  @NonNull
  static String duration(long seconds)
  {
    final long minutes = Math.max(0, (seconds + 59) / 60);
    if (minutes < 60)
      return minutes + " min";
    final long hours = minutes / 60;
    final long rest = minutes % 60;
    return rest == 0 ? hours + " h" : hours + " h " + rest + " min";
  }
}
