package app.organicmaps.livelocation;

import android.content.Context;
import android.text.InputType;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.organicmaps.R;
import app.organicmaps.sdk.Framework;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.util.UiUtils;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.List;
import java.util.Map;

/**
 * Live location (NLL): one contact's details (§11.4, §11.5): their state and position, the relay a
 * message to them or live updates from them need, how long the user shares with them, comparing codes,
 * hiding, renaming and deleting. Positions, arriving every few seconds, update their lines in place: a
 * rebuild would lose taps and move TalkBack's focus.
 */
public class ContactFragment extends LiveLocationFragment
{
  static final String ARG_CONTACT_ID = "contact_id";
  private static final int SHOW_ZOOM = 16;

  private boolean mClosing;
  // The lines a position updates.
  @Nullable
  private TextView mLastSeen;
  @Nullable
  private TextView mAccuracy;
  @Nullable
  private TextView mBattery;
  @Nullable
  private View mShowOnMap;

  @Override
  public void onPositions(@NonNull List<Position> positions)
  {
    if (mLastSeen == null)
      refresh();
    else
      showPosition();
  }

  @Override
  public void onDestroyView()
  {
    forgetPositionLines();
    super.onDestroyView();
  }

  @Nullable
  private String contactId()
  {
    return getArguments() != null ? getArguments().getString(ARG_CONTACT_ID) : null;
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    forgetPositionLines();
    final Context context = requireContext();
    final String id = contactId();
    final Contact contact = id != null ? LiveLocation.getContact(id) : null;
    if (contact == null)
    {
      // Deleted meanwhile: the screen goes, once this refresh is over.
      if (!mClosing)
      {
        mClosing = true;
        requireView().post(() -> {
          if (isAdded())
            host().close();
        });
      }
      return;
    }

    views.row(contact.name, LiveLocationText.status(context, contact, false), LiveLocationText.badge(context, contact),
              v -> rename(contact));
    if (contact.flagged)
      views.text(getString(R.string.live_location_flagged_warning, contact.name));
    if (contact.offerRemoval)
      views.text(getString(R.string.live_location_offer_removal, contact.name));
    if (contact.notMoved)
      views.text(getString(
          contact.moveOverdue ? R.string.live_location_move_overdue_message : R.string.live_location_not_moved_message,
          contact.name));
    // The labels are where the user changes their mind about a relay (§11.4).
    if (!contact.blockedRelay.isEmpty())
      views.row(getString(R.string.live_location_blocked, contact.name, contact.blockedRelay),
                getString(R.string.live_location_tap_to_allow), null,
                v -> allow(contact, contact.blockedRelay, ConsentRequest.Purpose.Sending));
    if (contact.liveUpdatesOff && !contact.liveRelay.isEmpty())
      views.row(getString(R.string.live_location_live_updates_need, contact.name, contact.liveRelay),
                getString(R.string.live_location_tap_to_allow), null,
                v -> allow(contact, contact.liveRelay, ConsentRequest.Purpose.LiveUpdates));

    if (contact.iShareUntil != null)
    {
      final long until = contact.iShareUntil;
      views.row(getString(R.string.live_location_you_share), LiveLocationText.until(context, until),
                getString(R.string.live_location_change),
                v -> LiveLocationDialogs.pickDuration(this, ShareDuration.of(until), duration -> {
                  if (!LiveLocation.extendSharing(contact.id, duration.until(System.currentTimeMillis() / 1000)))
                    LiveLocationDialogs.showMessage(requireActivity(), null,
                                                    getString(R.string.live_location_change_failed));
                }));
    }

    mLastSeen = views.text("");
    mAccuracy = views.text("");
    mBattery = views.text(getString(R.string.live_location_battery_low));
    views.toggle(getString(R.string.live_location_hide), getString(R.string.live_location_hide_summary), contact.hidden,
                 (button, checked) -> LiveLocation.setHidden(contact.id, checked));
    mShowOnMap = views.button(getString(R.string.live_location_show_on_map), v -> {
      final Position position = positionOf(contact.id);
      if (position == null)
        return;
      Framework.nativeZoomToPoint(position.lat, position.lon, SHOW_ZOOM, true);
      requireActivity().finish();
    });
    showPosition();

    if (!contact.verified || contact.flagged)
      views.outlinedButton(getString(R.string.live_location_compare_code), v -> compare(contact));
    if (contact.iShareUntil != null)
      views.redOutlinedButton(getString(R.string.live_location_stop_sharing_with, contact.name),
                              v -> stopSharingWith(contact));
    views.redOutlinedButton(getString(R.string.live_location_delete_contact), v -> delete(contact));
  }

  private void forgetPositionLines()
  {
    mLastSeen = null;
    mAccuracy = null;
    mBattery = null;
    mShowOnMap = null;
  }

  private void showPosition()
  {
    if (mLastSeen == null || mAccuracy == null || mBattery == null || mShowOnMap == null)
      return;
    final String id = contactId();
    final Position position = id != null ? positionOf(id) : null;
    UiUtils.showIf(position != null, mLastSeen, mAccuracy, mShowOnMap);
    UiUtils.showIf(position != null && position.low, mBattery);
    if (position == null)
      return;
    mLastSeen.setText(getString(R.string.live_location_last_seen, LiveLocationText.ago(position.timeMs)));
    mAccuracy.setText(getString(R.string.live_location_accuracy, Math.round(position.accuracy)));
  }

  /** The relay consent question, asked again: allowing it, or refusing it for good. */
  private void allow(@NonNull Contact contact, @NonNull String url, @NonNull ConsentRequest.Purpose purpose)
  {
    LiveLocationDialogs.showConsent(requireActivity(), new ConsentRequest(url, contact.name, purpose), null);
  }

  private void stopSharingWith(@NonNull Contact contact)
  {
    if (!LiveLocationShares.stopSharingWith(contact.id, Map.of()))
      LiveLocationDialogs.showMessage(requireActivity(), null, getString(R.string.live_location_change_failed));
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
