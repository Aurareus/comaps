package app.organicmaps.livelocation;

import android.os.Bundle;
import androidx.annotation.NonNull;
import app.organicmaps.R;

/**
 * Live location (NLL): what relays can see (docs/LIVE_LOCATION.md §11.6). Shown once when the feature
 * is first turned on, where the user turns it on when it is off, and from Settings, to read only.
 */
public class ExplanationFragment extends LiveLocationFragment
{
  static final String ARG_JUST_READ = "just_read";

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    views.header(getString(R.string.live_location_explain_title));
    views.text(getString(R.string.live_location_explain_1));
    views.text(getString(R.string.live_location_explain_2));
    views.text(getString(R.string.live_location_explain_3));
    views.text(getString(R.string.live_location_explain_4));
    views.text(getString(R.string.live_location_explain_5));
    views.text(getString(R.string.live_location_explain_6));
    views.text(getString(R.string.live_location_explain_7));

    final Bundle args = getArguments();
    if (args != null && args.getBoolean(ARG_JUST_READ))
    {
      views.button(getString(R.string.live_location_got_it), v -> requireActivity().finish());
      return;
    }
    if (!LiveLocationFeature.isEnabled(requireContext()))
    {
      views.button(getString(R.string.live_location_turn_on), v -> {
        LiveLocationFeature.setEnabled(requireContext(), true);
        LiveLocationFeature.setExplained(requireContext());
        host().continueAfterExplanation();
      });
      return;
    }
    views.button(getString(R.string.live_location_got_it), v -> {
      LiveLocationFeature.setExplained(requireContext());
      host().continueAfterExplanation();
    });
  }
}
