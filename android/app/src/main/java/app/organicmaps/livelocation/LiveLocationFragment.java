package app.organicmaps.livelocation;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import java.util.List;

/**
 * Live location (NLL): a screen built from the core's current state, and built again whenever what it
 * shows changes. By default that is the contacts and the share.
 */
abstract class LiveLocationFragment extends Fragment implements LiveLocation.Listener
{
  @Nullable
  private LiveLocationViews mViews;

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

  protected final void refresh()
  {
    if (mViews == null || !isAdded())
      return;
    mViews.clear();
    render(mViews);
  }

  protected abstract void render(@NonNull LiveLocationViews views);

  @Override
  public void onContacts(@NonNull List<Contact> contacts)
  {
    refresh();
  }

  @Override
  public void onSharing(@NonNull Sharing sharing)
  {
    refresh();
  }

  @NonNull
  protected LiveLocationActivity host()
  {
    return (LiveLocationActivity) requireActivity();
  }
}
