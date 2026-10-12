package app.organicmaps.livelocation;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import app.organicmaps.R;
import app.organicmaps.base.BaseToolbarActivity;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;

/**
 * Live location (NLL): its screens (docs/LIVE_LOCATION.md §11): contacts, adding a contact, sharing
 * and managing a share, a contact's details, settings, and what relays can see. While it is in front,
 * it asks the relay consent questions.
 */
public class LiveLocationActivity extends BaseToolbarActivity implements LiveLocationFeature.ConsentPresenter
{
  static final String EXTRA_SCREEN = "live_location_screen";
  static final String EXTRA_LINK = "live_location_link";
  static final String SCREEN_MANAGE = "manage";
  static final String SCREEN_JOIN = "join";
  static final String SCREEN_RESUME = "resume";
  static final String SCREEN_EXPLAIN = "explain";

  @Nullable
  private AlertDialog mConsentDialog;

  @NonNull
  public static Intent contactsIntent(@NonNull Context context)
  {
    return new Intent(context, LiveLocationActivity.class);
  }

  @NonNull
  public static Intent manageIntent(@NonNull Context context)
  {
    return contactsIntent(context).putExtra(EXTRA_SCREEN, SCREEN_MANAGE);
  }

  @NonNull
  public static Intent joinIntent(@NonNull Context context, @NonNull String link)
  {
    return contactsIntent(context).putExtra(EXTRA_SCREEN, SCREEN_JOIN).putExtra(EXTRA_LINK, link);
  }

  @NonNull
  public static Intent resumeIntent(@NonNull Context context)
  {
    return contactsIntent(context).putExtra(EXTRA_SCREEN, SCREEN_RESUME);
  }

  @NonNull
  public static Intent explanationIntent(@NonNull Context context)
  {
    return contactsIntent(context).putExtra(EXTRA_SCREEN, SCREEN_EXPLAIN);
  }

  @Override
  protected Class<? extends Fragment> getFragmentClass()
  {
    final String screen = getIntent().getStringExtra(EXTRA_SCREEN);
    if (!LiveLocationFeature.isEnabled(this) || SCREEN_EXPLAIN.equals(screen))
      return ExplanationFragment.class;
    if (SCREEN_MANAGE.equals(screen))
      return ManageSharingFragment.class;
    if (SCREEN_JOIN.equals(screen))
      return PairingFragment.class;
    if (SCREEN_RESUME.equals(screen))
      return ShareFragment.class;
    return ContactsFragment.class;
  }

  @Override
  protected int getToolbarTitle()
  {
    return R.string.live_location;
  }

  @Override
  protected void onStart()
  {
    super.onStart();
    LiveLocationFeature.attachConsentPresenter(this);
  }

  @Override
  protected void onStop()
  {
    LiveLocationFeature.detachConsentPresenter(this);
    if (mConsentDialog != null)
      mConsentDialog.dismiss();
    mConsentDialog = null;
    super.onStop();
  }

  @Override
  public void presentConsent(@NonNull ConsentRequest request)
  {
    mConsentDialog = LiveLocationDialogs.showConsent(this, request, LiveLocationFeature::onConsentAnswered);
  }

  /** A screen on top of this one; back returns. */
  void open(@NonNull Class<? extends Fragment> screen, @StringRes int title, @Nullable Bundle args)
  {
    stackFragment(screen, getString(title), args);
  }

  /** The explanation turned the feature on: the screen the user came for. */
  void continueAfterExplanation()
  {
    if (SCREEN_EXPLAIN.equals(getIntent().getStringExtra(EXTRA_SCREEN)))
    {
      finish();
      return;
    }
    replaceFragment(getFragmentClass(), getIntent().getExtras(), null);
  }
}
