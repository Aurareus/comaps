package app.organicmaps.livelocation;

import androidx.annotation.NonNull;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Live location (NLL): changes to the running share that more than one screen makes. */
final class LiveLocationShares
{
  private LiveLocationShares() {}

  static boolean isRecipient(@NonNull Sharing sharing, @NonNull String contactId)
  {
    for (Recipient recipient : sharing.recipients)
      if (recipient.contactId.equals(contactId))
        return true;
    return false;
  }

  /**
   * Stops sharing with `contactId` at once, adding `adding` (contact id -> end, 0: until stopped) in the
   * same change. Leaves out anyone whose end has just passed, which the core would refuse, and anyone added
   * who already shares. False if the core refused the change all the same.
   */
  static boolean stopSharingWith(@NonNull String contactId, @NonNull Map<String, Long> adding)
  {
    final long now = System.currentTimeMillis() / 1000;
    final Sharing sharing = LiveLocation.getSharing();
    final List<Recipient> rest = new ArrayList<>();
    for (Recipient recipient : sharing.recipients)
      if (!recipient.contactId.equals(contactId) && (recipient.until == 0 || recipient.until > now))
        rest.add(recipient);
    for (Map.Entry<String, Long> added : adding.entrySet())
      if (!added.getKey().equals(contactId) && !isRecipient(sharing, added.getKey())
          && (added.getValue() == 0 || added.getValue() > now))
        rest.add(new Recipient(added.getKey(), added.getValue()));
    if (!rest.isEmpty())
      return LiveLocation.changeSharing(rest);
    LiveLocation.stopSharing();
    return true;
  }
}
