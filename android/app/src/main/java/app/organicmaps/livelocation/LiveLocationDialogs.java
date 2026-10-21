package app.organicmaps.livelocation;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.GridView;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Consent;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.DotColor;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import app.organicmaps.sdk.util.DateUtils;
import app.organicmaps.util.Graphics;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.timepicker.MaterialTimePicker;
import com.google.android.material.timepicker.TimeFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;

/** Live location (NLL): the dialogs shared by the map and the live location screens. */
final class LiveLocationDialogs
{
  interface TextCheck
  {
    /** An error to show, or null when the text will do. */
    @Nullable
    String check(@NonNull String text);
  }

  interface TextDone
  {
    void done(@NonNull String text);
  }

  interface ConsentAnswered
  {
    void answered(@NonNull Consent consent);
  }

  interface DurationChosen
  {
    void chosen(@NonNull ShareDuration duration);
  }

  interface Rows
  {
    /** Adds the dialog's rows; `refresh` builds them again, e.g. after a change. */
    void render(@NonNull LiveLocationViews views, @NonNull Runnable refresh);
  }

  private LiveLocationDialogs() {}

  /**
   * Relay consent (docs/LIVE_LOCATION.md §11.4). The core keeps an approval and a refusal until revoked
   * in Settings; "Not now" asks again the next time the relay is needed, at most once per run.
   * `onAnswered` runs after an answer, not when the dialog goes with its activity.
   */
  @NonNull
  static AlertDialog showConsent(@NonNull Activity activity, @NonNull ConsentRequest request,
                                 @Nullable ConsentAnswered onAnswered)
  {
    final String message = switch (request.purpose)
    {
      case Pairing -> activity.getString(R.string.live_location_consent_pairing, request.url);
      case Viewing -> activity.getString(R.string.live_location_consent_viewing, request.contactName, request.url);
      case LiveUpdates ->
        activity.getString(R.string.live_location_consent_live_updates, request.contactName, request.url);
      case Sending -> activity.getString(R.string.live_location_consent_sending, request.contactName, request.url);
    };
    final DialogInterface.OnClickListener answer = (dialog, which) ->
    {
      final Consent consent = switch (which)
      {
        case DialogInterface.BUTTON_POSITIVE -> Consent.Allow;
        case DialogInterface.BUTTON_NEUTRAL -> Consent.Refuse;
        default -> Consent.NotNow;
      };
      LiveLocation.setConsent(request.url, consent, request.contactName);
      if (onAnswered != null)
        onAnswered.answered(consent);
    };
    return new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.live_location_consent_title)
        .setMessage(message)
        .setCancelable(false)
        .setPositiveButton(R.string.live_location_allow, answer)
        .setNegativeButton(R.string.live_location_not_now, answer)
        .setNeutralButton(R.string.live_location_dont_allow, answer)
        .show();
  }

  /** "For": 15 min, 1 hour, 8 hours, until stopped, or until a time picked on a clock (§11.3). */
  static void pickDuration(@NonNull Fragment fragment, @NonNull ShareDuration current, @NonNull DurationChosen chosen)
  {
    final Context context = fragment.requireContext();
    final ShareDuration[] choices = ShareDuration.CHOICES;
    final CharSequence[] names = new CharSequence[choices.length + 1];
    for (int i = 0; i < choices.length; ++i)
      names[i] = choices[i].label(context);
    names[choices.length] = context.getString(R.string.live_location_until_time);
    final int checked = current.choice() >= 0 ? current.choice() : choices.length;
    new MaterialAlertDialogBuilder(context)
        .setTitle(R.string.live_location_for)
        .setSingleChoiceItems(names, checked,
                              (dialog, which) -> {
                                dialog.dismiss();
                                if (which < choices.length)
                                  chosen.chosen(choices[which]);
                                else
                                  pickTime(fragment, current, chosen);
                              })
        .setNegativeButton(R.string.cancel, null)
        .show();
  }

  /** A time of day: today if it is still to come, otherwise tomorrow. */
  private static void pickTime(@NonNull Fragment fragment, @NonNull ShareDuration current,
                               @NonNull DurationChosen chosen)
  {
    final Calendar suggested = Calendar.getInstance();
    if (current.mUntil != 0)
      suggested.setTimeInMillis(current.mUntil * 1000);
    else
      suggested.add(Calendar.HOUR_OF_DAY, 1);
    final MaterialTimePicker picker =
        new MaterialTimePicker.Builder()
            .setTimeFormat(DateUtils.is24HourFormat(fragment.requireContext()) ? TimeFormat.CLOCK_24H
                                                                               : TimeFormat.CLOCK_12H)
            .setHour(suggested.get(Calendar.HOUR_OF_DAY))
            .setMinute(suggested.get(Calendar.MINUTE))
            .setTitleText(R.string.live_location_until_title)
            .build();
    picker.addOnPositiveButtonClickListener(v -> {
      final Calendar until = Calendar.getInstance();
      until.set(Calendar.HOUR_OF_DAY, picker.getHour());
      until.set(Calendar.MINUTE, picker.getMinute());
      until.set(Calendar.SECOND, 0);
      until.set(Calendar.MILLISECOND, 0);
      if (until.getTimeInMillis() <= System.currentTimeMillis())
        until.add(Calendar.DAY_OF_YEAR, 1);
      chosen.chosen(ShareDuration.endingAt(until.getTimeInMillis() / 1000));
    });
    picker.show(fragment.getChildFragmentManager(), "live_location_until");
  }

  /** After the process died while sharing (§8.5): resume, or forget the share. */
  @NonNull
  static AlertDialog showResume(@NonNull Activity activity, @NonNull Sharing sharing, @NonNull Runnable onResume)
  {
    final String names = LiveLocationText.joinNames(activity, LiveLocationText.namesOf(sharing.resumable));
    final long until = LiveLocationText.latestUntil(sharing.resumable);
    final String message = until == 0 ? activity.getString(R.string.live_location_resume, names)
                                      : activity.getString(R.string.live_location_resume_until, names,
                                                           LiveLocationText.time(activity, until));
    return new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.live_location_resume_title)
        .setMessage(message)
        .setCancelable(false)
        .setPositiveButton(R.string.live_location_resume_button, (dialog, which) -> onResume.run())
        .setNegativeButton(R.string.live_location_dont_resume, (dialog, which) -> LiveLocation.dismissResume())
        .show();
  }

  /** A list in a dialog, such as the relays in Settings, kept current by its own rows' actions. */
  @NonNull
  static AlertDialog showRows(@NonNull Activity activity, @StringRes int title, @NonNull Rows rows)
  {
    final LayoutInflater inflater = LayoutInflater.from(activity);
    final View view = inflater.inflate(R.layout.dialog_live_location_rows, null);
    final LiveLocationViews views = new LiveLocationViews(inflater, view.findViewById(R.id.live_location_content));
    final Runnable[] refresh = new Runnable[1];
    refresh[0] = () ->
    {
      views.clear();
      rows.render(views, refresh[0]);
    };
    refresh[0].run();
    return new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setView(view)
        .setPositiveButton(R.string.done, null)
        .show();
  }

  /** The dot colour contacts see: CoMaps' bookmark colours, or "Automatic", which leaves it to each of them. */
  static void showDotColors(@NonNull Activity activity, @NonNull List<DotColor> colors, @NonNull String current,
                            @NonNull TextDone chosen)
  {
    final GridView grid = (GridView) LayoutInflater.from(activity).inflate(R.layout.fragment_color_grid, null);
    grid.setAdapter(new ArrayAdapter<>(activity, 0, colors) {
      @NonNull
      @Override
      public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent)
      {
        final View view = convertView != null
                            ? convertView
                            : LayoutInflater.from(activity).inflate(R.layout.color_row, parent, false);
        final DotColor color = Objects.requireNonNull(getItem(position));
        final int argb = 0xFF000000 | color.rgb;
        final ImageView circle = view.findViewById(R.id.iv__color);
        circle.setImageDrawable(
            color.name.equals(current)
                ? Graphics.drawCircleAndImage(argb, R.dimen.track_circle_size, R.drawable.ic_done,
                                              R.dimen.bookmark_icon_size, activity)
                : Graphics.drawCircle(argb, R.dimen.select_color_circle_size, activity.getResources()));
        view.setContentDescription(LiveLocationText.colorName(activity, color.name));
        return view;
      }
    });
    final AlertDialog dialog =
        new MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.live_location_dot_color)
            .setMessage(R.string.live_location_dot_color_message)
            .setView(grid)
            .setNeutralButton(R.string.live_location_dot_color_automatic, (d, which) -> chosen.done(""))
            .setNegativeButton(R.string.cancel, null)
            .show();
    grid.setOnItemClickListener((parent, view, position, id) -> {
      dialog.dismiss();
      chosen.done(colors.get(position).name);
    });
  }

  @NonNull
  static AlertDialog showMessage(@NonNull Activity activity, @Nullable String title, @NonNull String message)
  {
    return new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setMessage(message)
        .setPositiveButton(R.string.ok, null)
        .show();
  }

  /** One line of text; the dialog stays open while `check` finds an error. */
  @NonNull
  static AlertDialog showText(@NonNull Activity activity, @StringRes int title, @Nullable String message,
                              @NonNull String initial, @Nullable String hint, int inputType, @NonNull TextCheck check,
                              @NonNull TextDone done)
  {
    final View view = LayoutInflater.from(activity).inflate(R.layout.dialog_live_location_text, null);
    final TextInputLayout layout = view.findViewById(R.id.live_location_text_layout);
    final TextInputEditText edit = view.findViewById(R.id.live_location_text);
    if (hint != null)
      layout.setPlaceholderText(hint);
    edit.setInputType(inputType);
    edit.setText(initial);
    edit.setSelection(initial.length());
    final AlertDialog dialog = new MaterialAlertDialogBuilder(activity)
                                   .setTitle(title)
                                   .setMessage(message)
                                   .setView(view)
                                   .setNegativeButton(R.string.cancel, null)
                                   .setPositiveButton(R.string.ok, null)
                                   .create();
    dialog.setOnShowListener(shown -> {
      final Button ok = dialog.getButton(DialogInterface.BUTTON_POSITIVE);
      ok.setOnClickListener(v -> {
        final String text = edit.getText() != null ? edit.getText().toString().trim() : "";
        final String error = check.check(text);
        if (error != null)
        {
          layout.setError(error);
          return;
        }
        dialog.dismiss();
        done.done(text);
      });
    });
    dialog.show();
    edit.requestFocus();
    return dialog;
  }
}
