package app.organicmaps.livelocation;

import android.text.InputType;
import androidx.annotation.NonNull;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Live location (NLL): its settings (§11.5): the user's name, their relays in order (the first that
 * works listens, D17), the relays allowed for contacts, the live update switches (D4), and deleting
 * everything.
 */
public class SettingsFragment extends LiveLocationFragment
{
  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Settings settings = LiveLocation.getSettings();
    if (settings == null)
      return;

    views.header(getString(R.string.live_location_your_name));
    views.row(settings.name.isEmpty() ? "—" : settings.name, null, null, v -> rename(settings.name));

    views.header(getString(R.string.live_location_relays));
    views.text(getString(R.string.live_location_relays_summary));
    final List<String> relays = settings.homeRelays;
    for (int i = 0; i < relays.size(); ++i)
    {
      final int index = i;
      views.row(relays.get(i), null, null, v -> relayActions(relays, index));
    }
    if (!relays.isEmpty() && !settings.defaultRelays.contains(relays.get(0)))
      views.text(getString(R.string.live_location_relays_first_not_default, relays.get(0)));
    if (relays.size() < 2)
      views.text(getString(R.string.live_location_relays_few));
    views.outlinedButton(getString(R.string.live_location_add_relay), v -> addRelay(relays));

    if (!settings.approved.isEmpty())
    {
      views.header(getString(R.string.live_location_approved_relays));
      for (String[] approval : settings.approved)
      {
        final String url = approval[0];
        views.row(url, getString(R.string.live_location_approved_for, approval[1]), null,
                  v
                  -> new MaterialAlertDialogBuilder(requireActivity())
                         .setTitle(url)
                         .setNegativeButton(R.string.cancel, null)
                         .setPositiveButton(R.string.live_location_revoke,
                                            (dialog, which) -> {
                                              LiveLocation.revokeConsent(url);
                                              refresh();
                                            })
                         .show());
      }
    }

    views.header(getString(R.string.live_location));
    views.toggle(getString(R.string.live_location_request_live), settings.requestLive,
                 (button, checked) -> LiveLocation.setRequestLive(checked));
    views.toggle(getString(R.string.live_location_allow_live), settings.allowLive,
                 (button, checked) -> LiveLocation.setAllowLive(checked));
    views.text(getString(R.string.live_location_low_battery, settings.lowBatteryStop));
    views.outlinedButton(getString(R.string.live_location_delete_all),
                         v -> LiveLocationSettingsSwitch.confirmDeletion(requireActivity()));
  }

  private void rename(@NonNull String current)
  {
    LiveLocationDialogs.showText(requireActivity(), R.string.live_location_your_name_title,
                                 getString(R.string.live_location_your_name_message), current, null,
                                 InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS, text -> {
                                   if (text.isEmpty())
                                     return getString(R.string.live_location_name_empty);
                                   if (text.getBytes(StandardCharsets.UTF_8).length > 64)
                                     return getString(R.string.live_location_name_too_long);
                                   return null;
                                 }, name -> {
                                   LiveLocation.setName(name);
                                   refresh();
                                 });
  }

  private void relayActions(@NonNull List<String> relays, int index)
  {
    final List<CharSequence> items = new ArrayList<>();
    final boolean canMoveUp = index > 0;
    if (canMoveUp)
      items.add(getString(R.string.live_location_move_up));
    if (relays.size() > 1)
      items.add(getString(R.string.live_location_remove));
    if (items.isEmpty())
      return;
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(relays.get(index))
        .setItems(items.toArray(new CharSequence[0]),
                  (dialog, which) -> {
                    final List<String> changed = new ArrayList<>(relays);
                    if (canMoveUp && which == 0)
                      changed.add(index - 1, changed.remove(index));
                    else
                      changed.remove(index);
                    LiveLocation.setHomeRelays(changed);
                    refresh();
                  })
        .show();
  }

  private void addRelay(@NonNull List<String> relays)
  {
    LiveLocationDialogs.showText(requireActivity(), R.string.live_location_add_relay, null, "wss://",
                                 getString(R.string.live_location_relay_hint), InputType.TYPE_TEXT_VARIATION_URI,
                                 text
                                 -> text.startsWith("wss://") && text.length() > 6 && !relays.contains(text)
                                        ? null
                                        : getString(R.string.live_location_relay_invalid),
                                 url -> {
                                   final List<String> changed = new ArrayList<>(relays);
                                   changed.add(url);
                                   if (!LiveLocation.setHomeRelays(changed))
                                     LiveLocationDialogs.showMessage(requireActivity(), null,
                                                                     getString(R.string.live_location_relay_invalid));
                                   refresh();
                                 });
  }
}
