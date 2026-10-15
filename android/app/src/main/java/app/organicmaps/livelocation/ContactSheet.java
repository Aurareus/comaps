package app.organicmaps.livelocation;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import app.organicmaps.R;
import app.organicmaps.sdk.Framework;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import java.util.List;

/**
 * Live location (NLL): the sheet a tap on a contact's dot opens over the map (docs/LIVE_LOCATION.md
 * §11.4): name, status, last update and accuracy, "Center", "Hide", and the contact's screen.
 */
public class ContactSheet extends BottomSheetDialogFragment implements LiveLocation.Listener
{
  private static final String TAG = "live_location_contact_sheet";
  private static final String ARG_CONTACT_ID = "contact_id";
  private static final int CENTER_ZOOM = 16;

  @Nullable
  private LiveLocationViews mViews;

  /** One sheet at a time: a tap on another dot replaces it. */
  public static void open(@NonNull FragmentManager manager, @NonNull String contactId)
  {
    if (manager.isStateSaved())
      return;
    final Fragment open = manager.findFragmentByTag(TAG);
    if (open instanceof ContactSheet)
      ((ContactSheet) open).dismiss();
    final ContactSheet sheet = new ContactSheet();
    final Bundle args = new Bundle();
    args.putString(ARG_CONTACT_ID, contactId);
    sheet.setArguments(args);
    sheet.show(manager, TAG);
  }

  @Nullable
  @Override
  public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                           @Nullable Bundle savedInstanceState)
  {
    final View root = inflater.inflate(R.layout.fragment_live_location, container, false);
    mViews = new LiveLocationViews(inflater, root.findViewById(R.id.live_location_content));
    return root;
  }

  @Override
  public void onStart()
  {
    super.onStart();
    LiveLocation.addListener(this);
    refresh();
  }

  @Override
  public void onStop()
  {
    LiveLocation.removeListener(this);
    super.onStop();
  }

  @Override
  public void onDestroyView()
  {
    mViews = null;
    super.onDestroyView();
  }

  @Override
  public void onContacts(@NonNull List<Contact> contacts)
  {
    refresh();
  }

  @Override
  public void onPositions(@NonNull List<Position> positions)
  {
    refresh();
  }

  private void refresh()
  {
    if (mViews == null || !isAdded())
      return;
    final String id = requireArguments().getString(ARG_CONTACT_ID, "");
    final Contact contact = LiveLocation.getContact(id);
    if (contact == null || contact.hidden)
    {
      // Deleted, hidden, or the feature turned off meanwhile.
      dismissAllowingStateLoss();
      return;
    }
    mViews.clear();
    render(mViews, contact);
  }

  private void render(@NonNull LiveLocationViews views, @NonNull Contact contact)
  {
    final Context context = requireContext();
    views.row(contact.name, LiveLocationText.status(context, contact), LiveLocationText.badge(context, contact), null);
    final Position position = positionOf(contact.id);
    if (position != null)
    {
      views.text(getString(R.string.live_location_last_seen, LiveLocationText.ago(position.timeMs)));
      views.text(getString(R.string.live_location_accuracy, Math.round(position.accuracy)));
      views.button(getString(R.string.live_location_center), v -> {
        Framework.nativeZoomToPoint(position.lat, position.lon, CENTER_ZOOM, true);
        dismiss();
      });
    }
    views.toggle(getString(R.string.live_location_hide), false,
                 (button, checked) -> LiveLocation.setHidden(contact.id, checked));
    views.text(getString(R.string.live_location_hide_summary));
    views.outlinedButton(getString(R.string.live_location_contact_details), v -> {
      startActivity(LiveLocationActivity.contactIntent(context, contact.id));
      dismiss();
    });
  }

  @Nullable
  private static Position positionOf(@NonNull String contactId)
  {
    for (Position position : LiveLocation.getPositions())
      if (position.contactId.equals(contactId))
        return position;
    return null;
  }
}
