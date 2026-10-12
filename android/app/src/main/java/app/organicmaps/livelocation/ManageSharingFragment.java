package app.organicmaps.livelocation;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Recipient;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.ArrayList;
import java.util.List;

/** Live location (NLL): "Manage sharing" (§11.3): stop or extend per person, add people, stop all. */
public class ManageSharingFragment extends LiveLocationFragment
{
  private static final long EXTEND_SECONDS = 60 * 60;

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Context context = requireContext();
    final Sharing sharing = LiveLocation.getSharing();
    if (!sharing.active)
    {
      views.text(getString(R.string.live_location_not_sharing));
      views.button(getString(R.string.live_location_share_my_location),
                   v -> host().open(ShareFragment.class, R.string.live_location_share_my_location, null));
      return;
    }
    if (sharing.live)
      views.text(getString(R.string.live_location_live_now));
    for (Recipient recipient : sharing.recipients)
    {
      final Contact contact = LiveLocation.getContact(recipient.contactId);
      final String name = contact != null ? contact.name : "?";
      views.row(name,
                recipient.until == 0
                    ? getString(R.string.live_location_until_you_stop)
                    : getString(R.string.live_location_until, LiveLocationText.time(context, recipient.until)),
                null, v -> actions(name, recipient, sharing));
    }
    final Bundle add = new Bundle();
    add.putBoolean(ShareFragment.ARG_ADD, true);
    views.button(getString(R.string.live_location_add_people),
                 v -> host().open(ShareFragment.class, R.string.live_location_add_people, add));
    views.outlinedButton(getString(R.string.live_location_stop_all), v -> LiveLocation.stopSharing());
  }

  private void actions(@NonNull String name, @NonNull Recipient recipient, @NonNull Sharing sharing)
  {
    final List<CharSequence> items = new ArrayList<>();
    if (recipient.until != 0)
      items.add(getString(R.string.live_location_extend));
    items.add(getString(R.string.live_location_stop_sharing_with, name));
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(name)
        .setItems(items.toArray(new CharSequence[0]),
                  (dialog, which) -> {
                    if (recipient.until != 0 && which == 0)
                    {
                      final long now = System.currentTimeMillis() / 1000;
                      LiveLocation.extendSharing(recipient.contactId, Math.max(now, recipient.until) + EXTEND_SECONDS);
                      return;
                    }
                    final List<Recipient> rest = new ArrayList<>();
                    for (Recipient other : sharing.recipients)
                      if (!other.contactId.equals(recipient.contactId))
                        rest.add(other);
                    if (rest.isEmpty())
                      LiveLocation.stopSharing();
                    else
                      LiveLocation.changeSharing(rest);
                  })
        .show();
  }
}
