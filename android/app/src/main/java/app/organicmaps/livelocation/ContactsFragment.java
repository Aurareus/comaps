package app.organicmaps.livelocation;

import android.content.Context;
import android.location.Location;
import android.os.Bundle;
import androidx.annotation.NonNull;
import app.organicmaps.MwmApplication;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.util.SharingUtils;
import java.util.List;

/**
 * Live location (NLL): "Share My Location" while the feature is on (§11.5): sending the current location
 * once, as the main menu did, sharing live or stopping, adding a contact, the share, open invites, and
 * the contacts.
 */
public class ContactsFragment extends LiveLocationFragment
{
  @Override
  public void onPairing(@NonNull Pairing pairing)
  {
    refresh();
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Context context = requireContext();
    if (LiveLocationFeature.hasStoreError())
    {
      views.text(getString(R.string.live_location_store_error));
      views.redOutlinedButton(getString(R.string.live_location_delete_all),
                              v -> LiveLocationSettingsSwitch.confirmDeletion(requireActivity()));
    }

    final Sharing sharing = LiveLocation.getSharing();
    final List<Contact> contacts = LiveLocation.getContacts();
    views.outlinedButton(getString(R.string.live_location_send_current_location), v -> sendCurrentLocation());
    // Without contacts there is nobody to share with: "Add contact" comes first.
    if (sharing.active)
      views.redButton(getString(R.string.live_location_stop_sharing_location), v -> LiveLocation.stopSharing());
    else if (!contacts.isEmpty())
      views.button(getString(R.string.live_location_share_my_location),
                   v -> host().open(ManageSharingFragment.class, R.string.live_location_manage_sharing, null));
    views.outlinedButton(getString(R.string.live_location_add_contact),
                         v -> host().open(PairingFragment.class, R.string.live_location_add_contact, null));

    if (sharing.active)
    {
      final int count = sharing.recipients.size();
      views.row(getResources().getQuantityString(R.plurals.live_location_sharing_with_count, count, count),
                LiveLocationText.joinNames(context, LiveLocationText.namesOf(sharing.recipients)),
                getString(R.string.live_location_manage),
                v -> host().open(ManageSharingFragment.class, R.string.live_location_manage_sharing, null));
    }

    for (Pairing pairing : LiveLocation.getPairings())
    {
      if (!PairingFragment.isOpen(pairing))
        continue;
      final Bundle args = new Bundle();
      args.putString(PairingFragment.ARG_PAIRING_ID, pairing.id);
      views.row(getString(R.string.live_location_pending_invite),
                pairing.peerName.isEmpty() ? getString(R.string.live_location_waiting) : pairing.peerName, null,
                v -> host().open(PairingFragment.class, R.string.live_location_add_contact, args));
    }

    views.header(getString(R.string.live_location_contacts));
    if (contacts.isEmpty())
      views.text(getString(R.string.live_location_no_contacts));
    for (Contact contact : contacts)
    {
      views.row(contact.name, LiveLocationText.status(context, contact), LiveLocationText.badge(context, contact),
                v -> {
                  final Bundle args = new Bundle();
                  args.putString(ContactFragment.ARG_CONTACT_ID, contact.id);
                  host().open(ContactFragment.class, R.string.live_location_contact_details, args);
                });
    }
  }

  /** The current location as a link, through the share sheet: what "Share My Location" does without this feature. */
  private void sendCurrentLocation()
  {
    final Location location = MwmApplication.from(requireContext()).getLocationHelper().getSavedLocation();
    if (location == null)
      LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.unknown_current_position));
    else
      SharingUtils.shareLocation(requireContext(), location);
  }
}
