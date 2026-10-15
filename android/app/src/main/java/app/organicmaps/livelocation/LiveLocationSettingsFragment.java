package app.organicmaps.livelocation;

import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.core.view.ViewCompat;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceGroup;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreferenceCompat;
import androidx.recyclerview.widget.RecyclerView;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import app.organicmaps.util.Utils;
import app.organicmaps.util.WindowInsetUtils.ScrollableContentInsetsListener;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Live location (NLL): Settings → Live location sharing (docs/LIVE_LOCATION.md §11.5): the switch,
 * then the user's name, relays in order (the first that works listens, D17), the relays allowed for
 * contacts, the live update switches (D4), and deleting everything. While the feature is off, the rows
 * show their titles only, greyed: the values live in the encrypted store, which only the running core
 * reads. Deleting stays possible.
 */
@Keep
public class LiveLocationSettingsFragment extends PreferenceFragmentCompat
{
  @Override
  public void onAttach(@NonNull Context context)
  {
    super.onAttach(context);
    Utils.detachFragmentIfCoreNotInitialized(context, this);
  }

  @Override
  public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey)
  {
    setPreferenceScreen(getPreferenceManager().createPreferenceScreen(requireContext()));
  }

  @Override
  public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
  {
    super.onViewCreated(view, savedInstanceState);
    final RecyclerView list = getListView();
    ViewCompat.setOnApplyWindowInsetsListener(list, new ScrollableContentInsetsListener(list));
  }

  @Override
  public void onResume()
  {
    super.onResume();
    build();
  }

  private void build()
  {
    if (!isAdded())
      return;
    final Context context = requireContext();
    final PreferenceScreen screen = getPreferenceScreen();
    screen.removeAll();

    final SwitchPreferenceCompat toggle = new SwitchPreferenceCompat(context);
    toggle.setKey(getString(R.string.pref_live_location));
    toggle.setPersistent(false);
    toggle.setWidgetLayoutResource(R.layout.preference_switch);
    toggle.setIcon(R.drawable.ic_live_location_settings);
    toggle.setSingleLineTitle(false);
    toggle.setTitle(R.string.live_location_setting);
    toggle.setSummary(getString(R.string.live_location_setting_where, getString(R.string.share_my_location)));
    screen.addPreference(toggle);
    LiveLocationSettingsSwitch.bind(this, toggle, () -> getListView().post(this::build));

    final Settings settings = LiveLocationFeature.isEnabled(context) ? LiveLocation.getSettings() : null;
    if (LiveLocationFeature.isEnabled(context) && LiveLocationFeature.hasStoreError())
      screen.addPreference(note(getString(R.string.live_location_store_error)));
    if (settings == null)
      addTitles(screen);
    else
      addSettings(screen, settings);

    screen.addPreference(row(getString(R.string.live_location_delete_all), null,
                             () -> LiveLocationSettingsSwitch.confirmDeletion(requireActivity(), this::build)));
  }

  /** Off: what is here, without any value. */
  private void addTitles(@NonNull PreferenceScreen screen)
  {
    for (@StringRes int title : new int[] {R.string.live_location_your_name, R.string.live_location_relays,
                                           R.string.live_location_approved_relays, R.string.live_location_request_live,
                                           R.string.live_location_allow_live, R.string.live_location_low_battery_title})
    {
      final Preference preference = row(getString(title), null, null);
      preference.setEnabled(false);
      screen.addPreference(preference);
    }
  }

  private void addSettings(@NonNull PreferenceScreen screen, @NonNull Settings settings)
  {
    final PreferenceGroup name = category(screen, R.string.live_location_your_name);
    name.addPreference(row(settings.name.isEmpty() ? "—" : settings.name, null, () -> rename(settings.name)));

    final PreferenceGroup relays = category(screen, R.string.live_location_relays);
    relays.addPreference(note(getString(R.string.live_location_relays_summary)));
    final List<String> homeRelays = settings.homeRelays;
    for (int i = 0; i < homeRelays.size(); ++i)
    {
      final int index = i;
      relays.addPreference(row(homeRelays.get(i), null, () -> relayActions(homeRelays, index)));
    }
    if (!homeRelays.isEmpty() && !settings.defaultRelays.contains(homeRelays.get(0)))
      relays.addPreference(note(getString(R.string.live_location_relays_first_not_default, homeRelays.get(0))));
    if (homeRelays.size() < 2)
      relays.addPreference(note(getString(R.string.live_location_relays_few)));
    relays.addPreference(row(getString(R.string.live_location_add_relay), null, () -> addRelay(homeRelays)));

    if (!settings.approved.isEmpty())
    {
      final PreferenceGroup approved = category(screen, R.string.live_location_approved_relays);
      for (String[] approval : settings.approved)
      {
        final String url = approval[0];
        approved.addPreference(
            row(url, getString(R.string.live_location_approved_for, approval[1]), () -> revoke(url)));
      }
    }

    final PreferenceGroup live = category(screen, R.string.live_location);
    live.addPreference(toggle(R.string.live_location_request_live, settings.requestLive, LiveLocation::setRequestLive));
    live.addPreference(toggle(R.string.live_location_allow_live, settings.allowLive, LiveLocation::setAllowLive));
    live.addPreference(note(getString(R.string.live_location_low_battery, settings.lowBatteryStop)));
  }

  @NonNull
  private PreferenceGroup category(@NonNull PreferenceScreen screen, @StringRes int title)
  {
    final PreferenceCategory category = new PreferenceCategory(requireContext());
    category.setTitle(title);
    category.setIconSpaceReserved(true);
    screen.addPreference(category);
    return category;
  }

  @NonNull
  private Preference row(@NonNull CharSequence title, @Nullable CharSequence summary, @Nullable Runnable onClick)
  {
    final Preference preference = new Preference(requireContext());
    preference.setPersistent(false);
    preference.setIconSpaceReserved(true);
    preference.setSingleLineTitle(false);
    preference.setTitle(title);
    preference.setSummary(summary);
    if (onClick == null)
      preference.setSelectable(false);
    else
      preference.setOnPreferenceClickListener(p -> {
        onClick.run();
        return true;
      });
    return preference;
  }

  /** A line of explanation. */
  @NonNull
  private Preference note(@NonNull CharSequence text)
  {
    final Preference preference = row("", text, null);
    preference.setTitle(null);
    return preference;
  }

  private interface OnToggle
  {
    void set(boolean value);
  }

  @NonNull
  private Preference toggle(@StringRes int title, boolean checked, @NonNull OnToggle onToggle)
  {
    final SwitchPreferenceCompat preference = new SwitchPreferenceCompat(requireContext());
    preference.setPersistent(false);
    preference.setIconSpaceReserved(true);
    preference.setSingleLineTitle(false);
    preference.setWidgetLayoutResource(R.layout.preference_switch);
    preference.setTitle(title);
    preference.setChecked(checked);
    preference.setOnPreferenceChangeListener((p, value) -> {
      onToggle.set((Boolean) value);
      return true;
    });
    return preference;
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
                                   build();
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
                    build();
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
                                   build();
                                 });
  }

  private void revoke(@NonNull String url)
  {
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(url)
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(R.string.live_location_revoke,
                           (dialog, which) -> {
                             LiveLocation.revokeConsent(url);
                             build();
                           })
        .show();
  }
}
