package app.organicmaps.livelocation;

import android.app.Activity;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AlertDialog;
import app.organicmaps.R;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

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

  private LiveLocationDialogs() {}

  /**
   * Relay consent (docs/LIVE_LOCATION.md §11.4). The core keeps either answer: an approval until
   * revoked, a refusal as "do not ask again". `onAnswered` runs after an answer, not when the dialog
   * goes with its activity.
   */
  @NonNull
  static AlertDialog showConsent(@NonNull Activity activity, @NonNull ConsentRequest request,
                                 @Nullable Runnable onAnswered)
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
      LiveLocation.setConsent(request.url, which == DialogInterface.BUTTON_POSITIVE, request.contactName);
      if (onAnswered != null)
        onAnswered.run();
    };
    return new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.live_location_consent_title)
        .setMessage(message)
        .setCancelable(false)
        .setPositiveButton(R.string.live_location_allow, answer)
        .setNegativeButton(R.string.live_location_not_now, answer)
        .show();
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
