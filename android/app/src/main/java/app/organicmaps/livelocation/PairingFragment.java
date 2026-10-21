package app.organicmaps.livelocation;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.organicmaps.R;
import app.organicmaps.base.OnBackPressListener;
import app.organicmaps.sdk.livelocation.LiveLocation;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Consent;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import io.nayuki.qrcodegen.QrCode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;

/**
 * Live location (NLL): adding a contact (docs/LIVE_LOCATION.md §11.2). The inviter shows a QR code,
 * or shares a link; the joiner opens one, or pastes it. A link opened from outside the app asks the
 * joiner first: opening it must not by itself send the joiner's name or add a contact. Both compare a
 * code, and the inviter decides. Leaving the screen does not stop the pairing: it goes on, and Share My
 * Location lists it. The inviter is asked first whether to cancel the invite or leave it waiting.
 */
public class PairingFragment extends LiveLocationFragment implements OnBackPressListener
{
  static final String ARG_PAIRING_ID = "pairing_id";
  private static final int QR_SIZE_DP = 240;
  private static final long TICK_MS = 30_000;

  @Nullable
  private String mPairingId;
  private boolean mStarted;
  private boolean mNeedsName;
  private boolean mConfirmJoin;
  private boolean mInvalid;
  private boolean mFailed;
  private boolean mDiffered;
  // A link whose relays the user all refused or put off: those relays, and the link.
  @NonNull
  private List<String> mNotAllowed = List.of();
  @Nullable
  private String mNotAllowedLink;
  private final Handler mHandler = new Handler(Looper.getMainLooper());
  private final Runnable mTick = new Runnable() {
    @Override
    public void run()
    {
      refresh();
      mHandler.postDelayed(this, TICK_MS);
    }
  };

  /** Still under way: worth going back to. */
  static boolean isOpen(@NonNull Pairing pairing)
  {
    return pairing.stage == Pairing.Stage.Waiting || pairing.stage == Pairing.Stage.CompareCode;
  }

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    if (savedInstanceState != null)
      mPairingId = savedInstanceState.getString(ARG_PAIRING_ID);
    else if (getArguments() != null)
      mPairingId = getArguments().getString(ARG_PAIRING_ID);
    mStarted = mPairingId != null;
  }

  @Override
  public void onSaveInstanceState(@NonNull Bundle outState)
  {
    super.onSaveInstanceState(outState);
    outState.putString(ARG_PAIRING_ID, mPairingId);
  }

  @Override
  public void onStart()
  {
    super.onStart();
    mHandler.postDelayed(mTick, TICK_MS);
    if (mStarted)
      return;
    mStarted = true;
    begin();
  }

  private void begin()
  {
    withName(() -> {
      if (link() != null)
      {
        mConfirmJoin = true;
        refresh();
      }
      else
      {
        invite(false);
      }
    });
  }

  /** The invite link this screen was opened with, from outside the app. */
  @Nullable
  private String link()
  {
    return getArguments() != null ? getArguments().getString(LiveLocationActivity.EXTRA_LINK) : null;
  }

  @Override
  public void onStop()
  {
    mHandler.removeCallbacks(mTick);
    super.onStop();
  }

  @Override
  public void onPairing(@NonNull Pairing pairing)
  {
    if (pairing.id.equals(mPairingId))
      refresh();
  }

  @Override
  protected void render(@NonNull LiveLocationViews views)
  {
    final Pairing pairing = mPairingId != null ? LiveLocation.getPairing(mPairingId) : null;
    if (pairing == null)
    {
      if (mNeedsName)
      {
        views.text(getString(R.string.live_location_your_name_message));
        views.button(getString(R.string.live_location_your_name_title), v -> begin());
      }
      else if (mConfirmJoin)
      {
        final Settings settings = LiveLocation.getSettings();
        views.text(getString(R.string.live_location_join_confirm, settings != null ? settings.name : ""));
        views.button(getString(R.string.live_location_connect), v -> {
          mConfirmJoin = false;
          final String link = link();
          if (link != null)
            join(link);
        });
        views.outlinedButton(getString(R.string.cancel), v -> close());
      }
      else if (mFailed)
      {
        views.text(getString(R.string.live_location_invite_failed));
      }
      else if (!mNotAllowed.isEmpty() && mNotAllowedLink != null)
      {
        final String link = mNotAllowedLink;
        views.text(getString(R.string.live_location_invite_relays_not_allowed, String.join(", ", mNotAllowed)));
        for (String url : mNotAllowed)
          views.button(getString(R.string.live_location_allow_relay, url), v -> {
            LiveLocation.setConsent(url, Consent.Allow, "");
            join(link);
          });
      }
      else if (mInvalid)
      {
        views.text(getString(R.string.live_location_invalid_invite));
        views.outlinedButton(getString(R.string.live_location_paste_invite), v -> paste());
      }
      else
      {
        views.text(getString(R.string.live_location_connecting));
      }
      return;
    }
    if (pairing.inviter)
      renderInviter(views, pairing);
    else
      renderJoiner(views, pairing);
  }

  private void renderInviter(@NonNull LiveLocationViews views, @NonNull Pairing pairing)
  {
    switch (pairing.stage)
    {
    case Waiting ->
    {
      if (pairing.byLink)
      {
        views.text(getString(R.string.live_location_link_waiting));
        views.text(expiresIn(pairing));
        if (!pairing.link.isEmpty())
          views.button(getString(R.string.share), v -> shareLink(pairing.link));
      }
      else
      {
        if (!pairing.link.isEmpty())
        {
          final int size = (int) (QR_SIZE_DP * getResources().getDisplayMetrics().density);
          final Bitmap qr = qrCode(pairing.link, size);
          views.image(qr, qr.getWidth());
        }
        views.text(getString(R.string.live_location_invite_hint));
        views.text(expiresIn(pairing));
        views.outlinedButton(getString(R.string.live_location_share_link), v -> {
          LiveLocation.cancelPairing(pairing.id);
          invite(true);
        });
        views.outlinedButton(getString(R.string.live_location_paste_invite), v -> paste());
      }
      views.redOutlinedButton(getString(R.string.live_location_cancel_invite), v -> {
        LiveLocation.cancelPairing(pairing.id);
        close();
      });
    }
    case CompareCode ->
    {
      if (pairing.byLink)
      {
        views.text(getString(R.string.live_location_wants_to_connect_by_link, pairing.peerName));
        views.code(pairing.sas);
        views.button(getString(R.string.live_location_codes_match_connect),
                     v -> LiveLocation.decide(pairing.id, true, true));
        views.outlinedButton(getString(R.string.live_location_connect_without_comparing),
                             v -> LiveLocation.decide(pairing.id, true, false));
      }
      else
      {
        views.text(getString(R.string.live_location_wants_to_connect_in_person, pairing.peerName));
        views.code(pairing.sas);
        views.button(getString(R.string.live_location_codes_match_connect),
                     v -> LiveLocation.decide(pairing.id, true, true));
      }
      views.outlinedButton(getString(R.string.live_location_decline),
                           v -> LiveLocation.decide(pairing.id, false, false));
    }
    default -> renderOutcome(views, pairing);
    }
  }

  private void renderJoiner(@NonNull LiveLocationViews views, @NonNull Pairing pairing)
  {
    switch (pairing.stage)
    {
    case Waiting ->
    {
      views.text(getString(R.string.live_location_connecting));
      views.text(getString(R.string.live_location_joiner_waiting));
      views.outlinedButton(getString(R.string.cancel), v -> {
        LiveLocation.cancelPairing(pairing.id);
        close();
      });
    }
    case CompareCode ->
    {
      views.text(getString(R.string.live_location_check_code));
      views.code(pairing.sas);
      views.button(getString(R.string.live_location_codes_match), v -> LiveLocation.confirmCode(pairing.id, true));
      views.outlinedButton(getString(R.string.live_location_codes_differ), v -> {
        mDiffered = true;
        LiveLocation.confirmCode(pairing.id, false);
      });
    }
    default -> renderOutcome(views, pairing);
    }
  }

  private void renderOutcome(@NonNull LiveLocationViews views, @NonNull Pairing pairing)
  {
    switch (pairing.stage)
    {
    case Connected ->
    {
      views.text(pairing.peerName.isEmpty() ? getString(R.string.live_location_connected)
                                            : getString(R.string.live_location_connected_with, pairing.peerName));
      views.button(getString(R.string.done), v -> close());
      return;
    }
    case Declined -> views.text(getString(R.string.live_location_pairing_declined));
    case Conflict -> views.text(getString(R.string.live_location_pairing_conflict));
    case Expired -> views.text(getString(R.string.live_location_pairing_expired));
    default ->
      views.text(getString(mDiffered ? R.string.live_location_codes_differ_message
                                     : R.string.live_location_pairing_cancelled));
    }
    if (pairing.inviter)
      views.button(getString(R.string.live_location_new_invite), v -> invite(false));
    else
      views.button(getString(R.string.done), v -> close());
  }

  @NonNull
  private String expiresIn(@NonNull Pairing pairing)
  {
    final long left = pairing.expiresAt - System.currentTimeMillis() / 1000;
    return getString(R.string.live_location_expires_in, LiveLocationText.duration(left));
  }

  /** Pairing needs this user's name: asks for it first if there is none. */
  private void withName(@NonNull Runnable then)
  {
    final Settings settings = LiveLocation.getSettings();
    if (settings != null && !settings.name.isEmpty())
    {
      then.run();
      return;
    }
    mNeedsName = true;
    refresh();
    LiveLocationDialogs.showText(
        requireActivity(), R.string.live_location_your_name_title, getString(R.string.live_location_your_name_message),
        "", null, InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS, this::checkName, name -> {
          if (isAdded() && LiveLocation.setName(name))
          {
            mNeedsName = false;
            then.run();
          }
        });
  }

  @Nullable
  private String checkName(@NonNull String name)
  {
    if (name.isEmpty())
      return getString(R.string.live_location_name_empty);
    if (name.getBytes(StandardCharsets.UTF_8).length > 64)
      return getString(R.string.live_location_name_too_long);
    return null;
  }

  private void invite(boolean byLink)
  {
    mInvalid = false;
    mDiffered = false;
    final Pairing pairing = LiveLocation.createInvite(byLink);
    mPairingId = pairing != null ? pairing.id : null;
    mFailed = pairing == null;
    if (pairing != null && byLink && !pairing.link.isEmpty())
      shareLink(pairing.link);
    refresh();
  }

  private void join(@NonNull String link)
  {
    mFailed = false;
    mInvalid = false;
    mDiffered = false;
    mNotAllowed = List.of();
    final Pairing pairing = LiveLocation.openInvite(link);
    if (pairing == null)
    {
      mInvalid = true;
      refresh();
      return;
    }
    if (pairing.stage == Pairing.Stage.NeedsConsent)
    {
      // Relay consent for the invite's relays, one after the other; then open it again.
      askConsent(new ArrayDeque<>(pairing.needsConsent), () -> join(link));
      return;
    }
    if (pairing.stage == Pairing.Stage.Cancelled && !pairing.needsConsent.isEmpty())
    {
      // Refused, or put off in this run: not an invalid invite.
      mPairingId = null;
      mNotAllowed = pairing.needsConsent;
      mNotAllowedLink = link;
      refresh();
      return;
    }
    mPairingId = pairing.id.isEmpty() ? null : pairing.id;
    mInvalid = mPairingId == null;
    refresh();
  }

  private void askConsent(@NonNull ArrayDeque<String> urls, @NonNull Runnable then)
  {
    if (!isAdded())
      return;
    if (urls.isEmpty())
    {
      then.run();
      return;
    }
    final String url = urls.removeFirst();
    LiveLocationDialogs.showConsent(requireActivity(), new ConsentRequest(url, "", ConsentRequest.Purpose.Pairing),
                                    consent -> askConsent(urls, then));
  }

  private void paste()
  {
    LiveLocationDialogs.showText(
        requireActivity(), R.string.live_location_paste_invite, null, "",
        getString(R.string.live_location_paste_invite_hint), InputType.TYPE_TEXT_VARIATION_URI,
        text
        -> LiveLocationInviteProcessor.isInvite(Uri.parse(text)) ? null
                                                                 : getString(R.string.live_location_invalid_invite),
        link -> {
          final Pairing current = mPairingId != null ? LiveLocation.getPairing(mPairingId) : null;
          if (current != null && current.inviter && isOpen(current))
            LiveLocation.cancelPairing(current.id);
          withName(() -> join(link));
        });
  }

  private void shareLink(@NonNull String link)
  {
    final Intent send = new Intent(Intent.ACTION_SEND)
                            .setType("text/plain")
                            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.live_location_invite_subject))
                            .putExtra(Intent.EXTRA_TEXT, link);
    startActivity(Intent.createChooser(send, getString(R.string.share)));
  }

  private void close()
  {
    host().close();
  }

  /** Leaving with an invite still open: cancel it, or leave it waiting. */
  @Override
  public boolean onBackPressed()
  {
    final Pairing pairing = mPairingId != null ? LiveLocation.getPairing(mPairingId) : null;
    if (pairing == null || !pairing.inviter || !isOpen(pairing))
      return false;
    new MaterialAlertDialogBuilder(requireActivity())
        .setTitle(R.string.live_location_leave_invite_title)
        .setMessage(pairing.stage == Pairing.Stage.CompareCode
                        ? getString(R.string.live_location_leave_invite_deciding, pairing.peerName)
                        : getString(R.string.live_location_leave_invite_message,
                                    LiveLocationText.duration(pairing.expiresAt - System.currentTimeMillis() / 1000)))
        .setPositiveButton(R.string.live_location_leave_invite_waiting, (dialog, which) -> close())
        .setNegativeButton(R.string.live_location_cancel_invite,
                           (dialog, which) -> {
                             LiveLocation.cancelPairing(pairing.id);
                             close();
                           })
        .show();
    return true;
  }

  /** Black on white, with the standard quiet zone, scaled by whole pixels to at most `sizePx`. */
  @NonNull
  static Bitmap qrCode(@NonNull String text, int sizePx)
  {
    final QrCode qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
    final int border = 4;
    final int modules = qr.size + 2 * border;
    final int scale = Math.max(1, sizePx / modules);
    final int px = modules * scale;
    final int[] pixels = new int[px * px];
    for (int y = 0; y < px; ++y)
      for (int x = 0; x < px; ++x)
        pixels[y * px + x] = qr.getModule(x / scale - border, y / scale - border) ? Color.BLACK : Color.WHITE;
    return Bitmap.createBitmap(pixels, px, px, Bitmap.Config.ARGB_8888);
  }
}
