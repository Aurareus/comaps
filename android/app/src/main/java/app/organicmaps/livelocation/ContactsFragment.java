package app.organicmaps.livelocation;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import java.util.List;

/** Live location (NLL): the contacts, the current share, and the way to everything else (§11.5). */
public class ContactsFragment extends LiveLocationFragment
{
  @Override
  public void onStart()
  {
    super.onStart();
    if (LiveLocationFeature.takeStoppedUnseen())
      LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_stopped_unseen));
  }

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
      views.outlinedButton(getString(R.string.live_location_delete_all),
                           v -> LiveLocationSettingsSwitch.confirmDeletion(requireActivity()));
    }

    final Sharing sharing = LiveLocation.getSharing();
    if (sharing.active)
    {
      final int count = sharing.recipients.size();
      views.row(getResources().getQuantityString(R.plurals.live_location_sharing_with_count, count, count),
                LiveLocationText.joinNames(context, LiveLocationText.namesOf(sharing.recipients)),
                getString(R.string.live_location_manage),
                v -> host().open(ManageSharingFragment.class, R.string.live_location_manage_sharing, null));
    }

    final List<Contact> contacts = LiveLocation.getContacts();
    if (!sharing.active)
      views
          .button(getString(R.string.live_location_share_my_location),
                  v -> host().open(ShareFragment.class, R.string.live_location_share_my_location, null))
          .setEnabled(!contacts.isEmpty());
    views.outlinedButton(getString(R.string.live_location_add_contact),
                         v -> host().open(PairingFragment.class, R.string.live_location_add_contact, null));

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
                  host().open(ContactFragment.class, R.string.live_location_contacts, args);
                });
    }

    views.header(getString(R.string.settings));
    views.row(getString(R.string.live_location_settings), null, null,
              v -> host().open(SettingsFragment.class, R.string.live_location_settings, null));
    views.row(getString(R.string.live_location_what_relays_see), null, null, v -> {
      final Bundle args = new Bundle();
      args.putBoolean(ExplanationFragment.ARG_FROM_CONTACTS, true);
      host().open(ExplanationFragment.class, R.string.live_location_what_relays_see, args);
    });
  }
}
