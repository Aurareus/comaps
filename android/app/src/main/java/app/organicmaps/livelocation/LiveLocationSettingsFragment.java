package app.organicmaps.livelocation;

import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import androidx.annotation.DrawableRes;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.core.view.ViewCompat;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreferenceCompat;
import androidx.recyclerview.widget.RecyclerView;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Consent;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import app.organicmaps.util.Utils;
import app.organicmaps.util.WindowInsetUtils.ScrollableContentInsetsListener;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.util.ArrayList;
import java.util.List;

/**
 * Live location (NLL): Settings → Live location sharing (docs/LIVE_LOCATION.md §11.5), laid out like the
 * other settings pages: the switch, what relays can see, then one row per setting with its value or an
 * explanation below the title. The relay lists open in dialogs. While the feature is off, or its data
 * cannot be read, the rows show their titles only, greyed: the values live in the encrypted store, which
 * only the running core reads. What relays can see and deleting stay usable.
 */
@Keep
public class LiveLocationSettingsFragment extends PreferenceFragmentCompat
{
  /** The levels at which sharing may stop, in percent; 0: never. */
  private static final int[] LOW_BATTERY_LEVELS = {0, 5, 10, 15, 20, 30};
  private static final int MAX_RELAYS = 4; // spec §11

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

    screen.addPreference(row(R.drawable.ic_live_location_info, getString(R.string.live_location_what_relays_see),
                             getString(R.string.live_location_what_relays_see_summary),
                             () -> startActivity(LiveLocationActivity.whatRelaysSeeIntent(context))));

    final boolean enabled = LiveLocationFeature.isEnabled(context);
    final Settings settings = enabled ? LiveLocation.getSettings() : null;
    final boolean readable = settings != null && settings.readable;
    if (enabled && !readable)
      screen.addPreference(note(getString(R.string.live_location_store_error)));
    if (readable)
      addSettings(screen, settings);
    else
      addTitles(screen);

    screen.addPreference(row(R.drawable.ic_live_location_delete, getString(R.string.live_location_delete_all),
                             getString(R.string.live_location_delete_all_summary),
                             () -> LiveLocationSettingsSwitch.confirmDeletion(requireActivity(), this::build)));
  }

  /** Off, or unreadable: what is here, without any value. */
  private void addTitles(@NonNull PreferenceScreen screen)
  {
    final int[][] rows = {{R.drawable.ic_profile, R.string.live_location_appear_as},
                          {R.drawable.ic_live_location_palette, R.string.live_location_dot_color},
                          {R.drawable.ic_live_location_relays, R.string.live_location_relays},
                          {R.drawable.ic_live_location_contacts, R.string.live_location_approved_relays},
                          {R.drawable.ic_live_location_view, R.string.live_location_request_live},
                          {R.drawable.ic_live_location_live_updates, R.string.live_location_allow_live},
                          {R.drawable.ic_live_location_battery, R.string.live_location_low_battery_title}};
    for (int[] row : rows)
    {
      final Preference preference = row(row[0], getString(row[1]), null, null);
      preference.setEnabled(false);
      screen.addPreference(preference);
    }
  }

  private void addSettings(@NonNull PreferenceScreen screen, @NonNull Settings settings)
  {
    screen.addPreference(row(R.drawable.ic_profile, getString(R.string.live_location_appear_as),
                             settings.name.isEmpty() ? getString(R.string.live_location_not_set) : settings.name,
                             () -> rename(settings.name)));
    screen.addPreference(
        row(R.drawable.ic_live_location_palette, getString(R.string.live_location_dot_color),
            LiveLocationText.colorName(requireContext(), settings.color),
            () -> LiveLocationDialogs.showDotColors(requireActivity(), settings.dotColors, settings.color, color -> {
              LiveLocation.setColor(color);
              build();
            })));
    screen.addPreference(row(R.drawable.ic_live_location_relays, getString(R.string.live_location_relays),
                             getString(R.string.live_location_relays_summary), this::showRelays));
    final String forContacts = settings.approved.isEmpty() && settings.declined.isEmpty()
                                 ? getString(R.string.live_location_approved_relays_none)
                                 : getString(R.string.live_location_approved_relays_count, settings.approved.size(),
                                             settings.declined.size());
    screen.addPreference(row(R.drawable.ic_live_location_contacts, getString(R.string.live_location_approved_relays),
                             forContacts, this::showContactRelays));
    screen.addPreference(toggle(R.drawable.ic_live_location_view, R.string.live_location_request_live,
                                R.string.live_location_request_live_summary, settings.requestLive,
                                LiveLocation::setRequestLive));
    screen.addPreference(toggle(R.drawable.ic_live_location_live_updates, R.string.live_location_allow_live,
                                R.string.live_location_allow_live_summary, settings.allowLive,
                                LiveLocation::setAllowLive));
    screen.addPreference(row(R.drawable.ic_live_location_battery, getString(R.string.live_location_low_battery_title),
                             lowBatteryName(settings.lowBatteryStop), () -> pickLowBattery(settings.lowBatteryStop)));
  }

  @NonNull
  private Preference row(@DrawableRes int icon, @NonNull CharSequence title, @Nullable CharSequence summary,
                         @Nullable Runnable onClick)
  {
    final Preference preference = new Preference(requireContext());
    preference.setPersistent(false);
    preference.setIcon(icon);
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
    final Preference preference = new Preference(requireContext());
    preference.setPersistent(false);
    preference.setIconSpaceReserved(true);
    preference.setSelectable(false);
    preference.setSummary(text);
    return preference;
  }

  private interface OnToggle
  {
    void set(boolean value);
  }

  @NonNull
  private Preference toggle(@DrawableRes int icon, @StringRes int title, @StringRes int summary, boolean checked,
                            @NonNull OnToggle onToggle)
  {
    final SwitchPreferenceCompat preference = new SwitchPreferenceCompat(requireContext());
    preference.setPersistent(false);
    preference.setIcon(icon);
    preference.setSingleLineTitle(false);
    preference.setWidgetLayoutResource(R.layout.preference_switch);
    preference.setTitle(title);
    preference.setSummary(summary);
    preference.setChecked(checked);
    preference.setOnPreferenceChangeListener((p, value) -> {
      onToggle.set((Boolean) value);
      return true;
    });
    return preference;
  }

  private void rename(@NonNull String current)
  {
    LiveLocationDialogs.showText(requireActivity(), R.string.live_location_appear_as,
                                 getString(R.string.live_location_your_name_message), current, null,
                                 InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS,
                                 text -> LiveLocationText.nameError(requireContext(), text), name -> {
                                   LiveLocation.setName(name);
                                   build();
                                 });
  }

  @NonNull
  private String lowBatteryName(int percent)
  {
    return percent == 0 ? getString(R.string.live_location_low_battery_never)
                        : getString(R.string.live_location_low_battery_at, percent);
  }

  private void pickLowBattery(int current)
  {
    final CharSequence[] names = new CharSequence[LOW_BATTERY_LEVELS.length];
    int checked = -1;
    for (int i = 0; i < names.length; ++i)
    {
      names[i] = lowBatteryName(LOW_BATTERY_LEVELS[i]);
      if (LOW_BATTERY_LEVELS[i] == current)
        checked = i;
    }
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(R.string.live_location_low_battery_title)
        .setSingleChoiceItems(names, checked,
                              (dialog, which) -> {
                                LiveLocation.setLowBatteryStop(LOW_BATTERY_LEVELS[which]);
                                dialog.dismiss();
                                build();
                              })
        .setNegativeButton(R.string.cancel, null)
        .show();
  }

  /** The home relays in order, each to move up or remove, and adding one. */
  private void showRelays()
  {
    LiveLocationDialogs.showRows(requireActivity(), R.string.live_location_relays, (views, refresh) -> {
      final Settings settings = LiveLocation.getSettings();
      if (settings == null)
        return;
      final List<String> relays = settings.homeRelays;
      views.text(getString(R.string.live_location_relays_summary));
      for (int i = 0; i < relays.size(); ++i)
      {
        final int index = i;
        views.row(relays.get(i), null, null, v -> relayActions(relays, index, refresh));
      }
      if (!relays.isEmpty() && !settings.defaultRelays.contains(relays.get(0)))
        views.text(getString(R.string.live_location_relays_first_not_default, relays.get(0)));
      if (relays.size() < 2)
        views.text(getString(R.string.live_location_relays_few));
      if (relays.size() < MAX_RELAYS)
        views.outlinedButton(getString(R.string.live_location_add_relay), v -> addRelay(relays, refresh));
    });
  }

  private void relayActions(@NonNull List<String> relays, int index, @NonNull Runnable refresh)
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
                    refresh.run();
                    build();
                  })
        .show();
  }

  private void addRelay(@NonNull List<String> relays, @NonNull Runnable refresh)
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
                                   refresh.run();
                                   build();
                                 });
  }

  /** The relays contacts use that the user answered about: allowed ones to revoke, refused ones to allow. */
  private void showContactRelays()
  {
    LiveLocationDialogs.showRows(requireActivity(), R.string.live_location_approved_relays, (views, refresh) -> {
      final Settings settings = LiveLocation.getSettings();
      if (settings == null)
        return;
      if (settings.approved.isEmpty() && settings.declined.isEmpty())
      {
        views.text(getString(R.string.live_location_approved_relays_empty));
        return;
      }
      if (!settings.approved.isEmpty())
      {
        views.header(getString(R.string.live_location_allowed));
        for (String[] approval : settings.approved)
        {
          final String url = approval[0];
          views.row(url, forContact(R.string.live_location_approved_for, approval[1]), null, v -> revoke(url, refresh));
        }
      }
      if (!settings.declined.isEmpty())
      {
        views.header(getString(R.string.live_location_refused));
        for (String[] refusal : settings.declined)
        {
          final String url = refusal[0];
          final String contact = refusal[1];
          views.row(url, forContact(R.string.live_location_refused_for, contact), null,
                    v -> allowRefused(url, contact, refresh));
        }
      }
    });
  }

  /** "Allowed for Bob"; a relay answered about while connecting does not name the contact. */
  @NonNull
  private String forContact(@StringRes int text, @NonNull String contact)
  {
    return contact.isEmpty() ? getString(R.string.live_location_when_connecting) : getString(text, contact);
  }

  private void revoke(@NonNull String url, @NonNull Runnable refresh)
  {
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(url)
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(R.string.live_location_revoke,
                           (dialog, which) -> {
                             LiveLocation.revokeConsent(url);
                             refresh.run();
                             build();
                           })
        .show();
  }

  private void allowRefused(@NonNull String url, @NonNull String contact, @NonNull Runnable refresh)
  {
    final String message = contact.isEmpty() ? getString(R.string.live_location_allow_refused_any, url)
                                             : getString(R.string.live_location_allow_refused, url, contact);
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(url)
        .setMessage(message)
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(R.string.live_location_allow,
                           (dialog, which) -> {
                             LiveLocation.setConsent(url, Consent.Allow, contact);
                             refresh.run();
                             build();
                           })
        .show();
  }
}
