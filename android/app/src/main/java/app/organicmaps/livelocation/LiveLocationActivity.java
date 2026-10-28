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
import app.organicmaps.base.OnBackPressListener;
import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import com.google.android.material.appbar.MaterialToolbar;
import java.util.ArrayList;

/**
 * Live location (NLL): its screens (docs/LIVE_LOCATION.md §11): Share My Location, adding a contact,
 * managing the share, a contact's details, and what relays can see. While it is in front, it asks the
 * relay consent questions and tells what the user must know. A screen on top of another has its own
 * title, back on the one below as soon as it goes, however it goes; and back asks the screen in front
 * first (OnBackPressListener).
 */
public class LiveLocationActivity extends BaseToolbarActivity implements LiveLocationFeature.Presenter
{
  static final String EXTRA_SCREEN = "live_location_screen";
  static final String EXTRA_LINK = "live_location_link";
  static final String SCREEN_MANAGE = "manage";
  static final String SCREEN_JOIN = "join";
  static final String SCREEN_RESUME = "resume";
  static final String SCREEN_EXPLAIN = "explain";
  static final String SCREEN_WHAT_RELAYS_SEE = "what_relays_see";
  static final String SCREEN_CONTACT = "contact";

  private static final String STATE_TITLES = "live_location_titles";

  @Nullable
  private AlertDialog mPresented; // a consent question or a message
  // The titles of the screens on top of the first, in order.
  private ArrayList<CharSequence> mTitles = new ArrayList<>();

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

  /** What relays can see, to read only, e.g. from Settings: also while the feature is off. */
  @NonNull
  public static Intent whatRelaysSeeIntent(@NonNull Context context)
  {
    return contactsIntent(context)
        .putExtra(EXTRA_SCREEN, SCREEN_WHAT_RELAYS_SEE)
        .putExtra(ExplanationFragment.ARG_JUST_READ, true);
  }

  /** One contact's screen, e.g. from the sheet of its dot on the map. */
  @NonNull
  public static Intent contactIntent(@NonNull Context context, @NonNull String contactId)
  {
    return contactsIntent(context)
        .putExtra(EXTRA_SCREEN, SCREEN_CONTACT)
        .putExtra(ContactFragment.ARG_CONTACT_ID, contactId);
  }

  @Override
  protected void onSafeCreate(@Nullable Bundle savedInstanceState)
  {
    super.onSafeCreate(savedInstanceState);
    if (savedInstanceState != null)
    {
      final ArrayList<CharSequence> titles = savedInstanceState.getCharSequenceArrayList(STATE_TITLES);
      if (titles != null)
        mTitles = titles;
    }
    getSupportFragmentManager().addOnBackStackChangedListener(this::showTitle);
    showTitle();
  }

  @Override
  protected void onSaveInstanceState(@NonNull Bundle outState)
  {
    super.onSaveInstanceState(outState);
    outState.putCharSequenceArrayList(STATE_TITLES, mTitles);
  }

  @Override
  public void onBackPressed()
  {
    final Fragment front = getSupportFragmentManager().findFragmentById(getFragmentContentResId());
    if (front instanceof OnBackPressListener && ((OnBackPressListener) front).onBackPressed())
      return;
    super.onBackPressed();
  }

  private void showTitle()
  {
    final int screens = getSupportFragmentManager().getBackStackEntryCount();
    while (mTitles.size() > screens)
      mTitles.remove(mTitles.size() - 1);
    final MaterialToolbar toolbar = getToolbar();
    if (toolbar == null)
      return;
    if (screens > 0 && screens == mTitles.size())
      toolbar.setTitle(mTitles.get(screens - 1));
    else
      toolbar.setTitle(getToolbarTitle());
  }

  @Override
  protected Class<? extends Fragment> getFragmentClass()
  {
    final String screen = getIntent().getStringExtra(EXTRA_SCREEN);
    if (!LiveLocationFeature.isEnabled(this) || SCREEN_EXPLAIN.equals(screen) || SCREEN_WHAT_RELAYS_SEE.equals(screen))
      return ExplanationFragment.class;
    if (SCREEN_MANAGE.equals(screen))
      return ManageSharingFragment.class;
    if (SCREEN_JOIN.equals(screen))
      return PairingFragment.class;
    if (SCREEN_RESUME.equals(screen))
      return ManageSharingFragment.class;
    if (SCREEN_CONTACT.equals(screen))
      return ContactFragment.class;
    return ContactsFragment.class;
  }

  @Override
  protected int getToolbarTitle()
  {
    final String screen = getIntent().getStringExtra(EXTRA_SCREEN);
    if (SCREEN_WHAT_RELAYS_SEE.equals(screen))
      return R.string.live_location_what_relays_see;
    if (!LiveLocationFeature.isEnabled(this) || SCREEN_EXPLAIN.equals(screen))
      return R.string.live_location_sharing;
    if (SCREEN_MANAGE.equals(screen))
      return R.string.live_location_manage_sharing;
    if (SCREEN_JOIN.equals(screen))
      return R.string.live_location_add_contact;
    if (SCREEN_RESUME.equals(screen))
      return R.string.live_location_manage_sharing;
    if (SCREEN_CONTACT.equals(screen))
      return R.string.live_location_contact_details;
    // The main menu's "Share My Location" leads here while the feature is on.
    return R.string.share_my_location;
  }

  @Override
  protected void onStart()
  {
    super.onStart();
    LiveLocationFeature.attachPresenter(this);
  }

  @Override
  protected void onStop()
  {
    LiveLocationFeature.detachPresenter(this);
    if (mPresented != null)
      mPresented.dismiss();
    mPresented = null;
    super.onStop();
  }

  @Override
  public void presentConsent(@NonNull ConsentRequest request)
  {
    mPresented = LiveLocationDialogs.showConsent(this, request, consent -> LiveLocationFeature.onPresented());
  }

  @Override
  public void presentMessage(@StringRes int message)
  {
    mPresented = LiveLocationDialogs.showNotice(this, message, LiveLocationFeature::onPresented);
  }

  /** A screen on top of this one; back returns. */
  void open(@NonNull Class<? extends Fragment> screen, @StringRes int title, @Nullable Bundle args)
  {
    mTitles.add(getString(title));
    stackFragment(screen, null, args);
    showTitle();
  }

  /** Leaves the screen in front, as back does, without asking it. */
  void close()
  {
    if (getSupportFragmentManager().getBackStackEntryCount() > 0)
      getSupportFragmentManager().popBackStack();
    else
      finish();
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
    showTitle();
  }
}
