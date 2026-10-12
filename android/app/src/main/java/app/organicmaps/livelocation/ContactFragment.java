package app.organicmaps.livelocation;

import android.content.Context;
import android.text.InputType;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.organicmaps.R;
import app.organicmaps.sdk.Framework;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.List;

/** Live location (NLL): one contact (§11.4, §11.5): position, verification, hiding, renaming, deleting. */
public class ContactFragment extends LiveLocationFragment
{
  static final String ARG_CONTACT_ID = "contact_id";
  private static final int SHOW_ZOOM = 16;

  @Override
  public void onPositions(@NonNull List<Position> positions)
  {
    refresh();
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Context context = requireContext();
    final String id = getArguments() != null ? getArguments().getString(ARG_CONTACT_ID) : null;
    final Contact contact = id != null ? LiveLocation.getContact(id) : null;
    if (contact == null)
    {
      // Deleted meanwhile.
      getParentFragmentManager().popBackStack();
      return;
    }

    views.row(contact.name, LiveLocationText.status(context, contact), LiveLocationText.badge(context, contact),
              v -> rename(contact));
    if (contact.flagged)
      views.text(getString(R.string.live_location_flagged_warning, contact.name));
    if (contact.offerRemoval)
    {
      views.text(getString(R.string.live_location_offer_removal, contact.name));
      views.outlinedButton(getString(R.string.live_location_delete_contact), v -> delete(contact));
    }
    if (contact.liveUpdatesOff)
    {
      // The label is where the user changes their mind about the relay (§11.4).
      views.text(getString(R.string.live_location_live_updates_off_message, contact.name, contact.liveRelay));
      if (!contact.liveRelay.isEmpty())
        views.outlinedButton(getString(R.string.live_location_allow_relay, contact.liveRelay),
                             v -> LiveLocation.setConsent(contact.liveRelay, true, contact.name));
    }

    final Position position = positionOf(contact.id);
    if (position != null)
    {
      views.text(getString(R.string.live_location_last_seen, LiveLocationText.ago(position.timeMs)));
      views.text(getString(R.string.live_location_accuracy, Math.round(position.accuracy)));
      views.button(getString(R.string.live_location_show_on_map), v -> {
        Framework.nativeZoomToPoint(position.lat, position.lon, SHOW_ZOOM, true);
        requireActivity().finish();
      });
    }

    if (!contact.verified || contact.flagged)
      views.outlinedButton(getString(R.string.live_location_compare_code), v -> compare(contact));
    views.toggle(getString(R.string.live_location_hide), contact.hidden,
                 (button, checked) -> LiveLocation.setHidden(contact.id, checked));
    views.text(getString(R.string.live_location_hide_summary));
    views.outlinedButton(getString(R.string.live_location_delete_contact), v -> delete(contact));
  }

  @Nullable
  private static Position positionOf(@NonNull String contactId)
  {
    for (Position position : LiveLocation.getPositions())
      if (position.contactId.equals(contactId))
        return position;
    return null;
  }

  private void rename(@NonNull Contact contact)
  {
    LiveLocationDialogs.showText(requireActivity(), R.string.live_location_rename, null, contact.name, null,
                                 InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS,
                                 text
                                 -> text.isEmpty() ? getString(R.string.live_location_name_empty) : null,
                                 name -> LiveLocation.renameContact(contact.id, name));
  }

  /** The codes compared later (§11.2): verified, and a flag is cleared; if they differ, delete. */
  private void compare(@NonNull Contact contact)
  {
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(R.string.live_location_compare_code)
        .setMessage(getString(R.string.live_location_compare_code_message, contact.name) + "\n\n" + contact.sas)
        .setPositiveButton(R.string.live_location_codes_match, (dialog, which) -> LiveLocation.markVerified(contact.id))
        .setNegativeButton(R.string.live_location_codes_differ, (dialog, which) -> delete(contact))
        .setNeutralButton(R.string.cancel, null)
        .show();
  }

  private void delete(@NonNull Contact contact)
  {
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(R.string.live_location_delete_contact)
        .setMessage(getString(R.string.live_location_delete_contact_confirm, contact.name))
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(R.string.live_location_delete, (dialog, which) -> LiveLocation.deleteContact(contact.id))
        .show();
  }
}
