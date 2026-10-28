package app.organicmaps.livelocation;

import android.graphics.Bitmap;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.widget.TextViewCompat;
import app.organicmaps.R;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.materialswitch.MaterialSwitch;

/** Live location (NLL): the screens' rows, added to a column in order. */
final class LiveLocationViews
{
  @NonNull
  private final LayoutInflater mInflater;
  @NonNull
  private final LinearLayout mContent;

  LiveLocationViews(@NonNull LayoutInflater inflater, @NonNull LinearLayout content)
  {
    mInflater = inflater;
    mContent = content;
  }

  void clear()
  {
    mContent.removeAllViews();
  }

  @NonNull
  TextView header(@NonNull CharSequence text)
  {
    final TextView view = (TextView) mInflater.inflate(R.layout.item_live_location_header, mContent, false);
    view.setText(text);
    mContent.addView(view);
    return view;
  }

  @NonNull
  TextView text(@NonNull CharSequence text)
  {
    final TextView view = (TextView) mInflater.inflate(R.layout.item_live_location_text, mContent, false);
    view.setText(text);
    mContent.addView(view);
    return view;
  }

  /** A large line, for a pairing code. */
  @NonNull
  TextView code(@NonNull String code)
  {
    final TextView view = text(code);
    TextViewCompat.setTextAppearance(view, R.style.MwmTextAppearance_Title);
    view.setTextSize(34);
    view.setGravity(Gravity.CENTER);
    view.setTextIsSelectable(true);
    return view;
  }

  @NonNull
  MaterialButton button(@NonNull CharSequence text, @NonNull View.OnClickListener onClick)
  {
    return addButton(R.layout.item_live_location_button, text, onClick);
  }

  @NonNull
  MaterialButton outlinedButton(@NonNull CharSequence text, @NonNull View.OnClickListener onClick)
  {
    return addButton(R.layout.item_live_location_button_outlined, text, onClick);
  }

  /** The main action, when it stops something. */
  @NonNull
  MaterialButton redButton(@NonNull CharSequence text, @NonNull View.OnClickListener onClick)
  {
    return addButton(R.layout.item_live_location_button_red, text, onClick);
  }

  /** Another action, when it stops or deletes something. */
  @NonNull
  MaterialButton redOutlinedButton(@NonNull CharSequence text, @NonNull View.OnClickListener onClick)
  {
    return addButton(R.layout.item_live_location_button_outlined_red, text, onClick);
  }

  @NonNull
  View row(@NonNull CharSequence title, @Nullable CharSequence subtitle, @Nullable CharSequence badge,
           @Nullable View.OnClickListener onClick)
  {
    final View view = mInflater.inflate(R.layout.item_live_location_row, mContent, false);
    setRow(view, title, subtitle, badge);
    if (onClick != null)
      view.setOnClickListener(onClick);
    else
      view.setBackground(null);
    mContent.addView(view);
    return view;
  }

  /** New texts for a row made by {@link #row}, in place. */
  static void setRow(@NonNull View row, @NonNull CharSequence title, @Nullable CharSequence subtitle,
                     @Nullable CharSequence badge)
  {
    ((TextView) row.findViewById(R.id.live_location_row_title)).setText(title);
    setOptional(row.findViewById(R.id.live_location_row_subtitle), subtitle);
    setOptional(row.findViewById(R.id.live_location_row_badge), badge);
  }

  @NonNull
  MaterialCheckBox check(@NonNull CharSequence title, @Nullable CharSequence warning, boolean checked, boolean enabled,
                         @NonNull CompoundButton.OnCheckedChangeListener onChange)
  {
    final View view = mInflater.inflate(R.layout.item_live_location_check, mContent, false);
    final MaterialCheckBox box = view.findViewById(R.id.live_location_check);
    ((TextView) view.findViewById(R.id.live_location_check_title)).setText(title);
    setOptional(view.findViewById(R.id.live_location_check_warning), warning);
    box.setChecked(checked);
    box.setEnabled(enabled);
    box.setOnCheckedChangeListener(onChange);
    view.setOnClickListener(v -> {
      if (box.isEnabled())
        box.toggle();
    });
    readAsOne(view, box, CheckBox.class);
    mContent.addView(view);
    return box;
  }

  /** A setting that is on or off, with what it does below its title. */
  @NonNull
  MaterialSwitch toggle(@NonNull CharSequence title, @Nullable CharSequence subtitle, boolean checked,
                        @NonNull CompoundButton.OnCheckedChangeListener onChange)
  {
    final View view = mInflater.inflate(R.layout.item_live_location_switch_row, mContent, false);
    ((TextView) view.findViewById(R.id.live_location_switch_title)).setText(title);
    setOptional(view.findViewById(R.id.live_location_switch_subtitle), subtitle);
    final MaterialSwitch toggle = view.findViewById(R.id.live_location_switch_toggle);
    toggle.setChecked(checked);
    toggle.setOnCheckedChangeListener(onChange);
    view.setOnClickListener(v -> toggle.toggle());
    readAsOne(view, toggle, Switch.class);
    mContent.addView(view);
    return toggle;
  }

  /**
   * One stop for a screen reader: the row reads its texts with the button's state, and a double tap toggles it.
   * Otherwise the button was a second stop, without a label.
   */
  private static void readAsOne(@NonNull View row, @NonNull CompoundButton button, @NonNull Class<?> role)
  {
    button.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
    ViewCompat.setAccessibilityDelegate(row, new AccessibilityDelegateCompat() {
      @Override
      public void onInitializeAccessibilityNodeInfo(@NonNull View host, @NonNull AccessibilityNodeInfoCompat info)
      {
        super.onInitializeAccessibilityNodeInfo(host, info);
        info.setClassName(role.getName());
        info.setCheckable(true);
        info.setChecked(button.isChecked());
        info.setEnabled(button.isEnabled());
      }
    });
  }

  @NonNull
  ImageView image(@NonNull Bitmap bitmap, int sizePx)
  {
    final ImageView view = new ImageView(mContent.getContext());
    view.setImageBitmap(bitmap);
    view.setAdjustViewBounds(true);
    final LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(sizePx, sizePx);
    params.gravity = Gravity.CENTER_HORIZONTAL;
    final int margin = mContent.getResources().getDimensionPixelSize(R.dimen.margin_base);
    params.setMargins(margin, margin, margin, margin);
    mContent.addView(view, params);
    return view;
  }

  @NonNull
  private MaterialButton addButton(int layout, @NonNull CharSequence text, @NonNull View.OnClickListener onClick)
  {
    final MaterialButton button = (MaterialButton) mInflater.inflate(layout, mContent, false);
    button.setText(text);
    button.setOnClickListener(onClick);
    mContent.addView(button);
    return button;
  }

  private static void setOptional(@NonNull TextView view, @Nullable CharSequence text)
  {
    if (text == null || text.length() == 0)
    {
      view.setVisibility(View.GONE);
      return;
    }
    view.setText(text);
    view.setVisibility(View.VISIBLE);
  }
}
