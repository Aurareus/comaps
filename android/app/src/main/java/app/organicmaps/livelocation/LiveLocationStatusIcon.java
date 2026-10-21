package app.organicmaps.livelocation;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.content.res.AppCompatResources;
import app.organicmaps.R;
import java.util.Objects;

/**
 * Live location (NLL): the sharing indicator's icon (ic_live_location_status) with the number of people
 * the user shares with cut out of the pin's head, so that the button shows through. Tinting it, as the
 * blinking does, tints the whole icon.
 */
public final class LiveLocationStatusIcon extends Drawable
{
  // In the icon's 24-unit viewport: the pin's head is centred at (12, 9) in a group scaled by 0.62, inside
  // one scaled by 1.23, both around (12, 12).
  private static final float VIEWPORT = 24;
  private static final float SCALE = 0.62f * 1.23f;
  private static final float HEAD_X = 12;
  private static final float HEAD_Y = 12 + (9 - 12) * SCALE;
  // Text sizes for one, two and three characters, and how far below the centre the baseline is.
  private static final float[] TEXT_SIZES = {7.6f * SCALE, 5.6f * SCALE, 4.2f * SCALE};
  private static final float BASELINE = 0.36f;

  @NonNull
  private final Drawable mIcon;
  @NonNull
  private final Paint mCut = new Paint(Paint.ANTI_ALIAS_FLAG);
  @NonNull
  private String mText = "";

  public LiveLocationStatusIcon(@NonNull Context context)
  {
    mIcon =
        Objects.requireNonNull(AppCompatResources.getDrawable(context, R.drawable.ic_live_location_status)).mutate();
    mCut.setTypeface(Typeface.DEFAULT_BOLD);
    mCut.setTextAlign(Paint.Align.CENTER);
    mCut.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.DST_OUT));
  }

  public void setCount(int count)
  {
    final String text = count <= 0 ? "" : count > 99 ? "99+" : String.valueOf(count);
    if (text.equals(mText))
      return;
    mText = text;
    invalidateSelf();
  }

  @Override
  public void draw(@NonNull Canvas canvas)
  {
    final Rect bounds = getBounds();
    final int layer = canvas.saveLayer(bounds.left, bounds.top, bounds.right, bounds.bottom, null);
    mIcon.draw(canvas);
    if (!mText.isEmpty())
    {
      final float unit = bounds.width() / VIEWPORT;
      final float size = TEXT_SIZES[Math.min(mText.length(), TEXT_SIZES.length) - 1] * unit;
      mCut.setTextSize(size);
      canvas.drawText(mText, bounds.left + HEAD_X * unit, bounds.top + HEAD_Y * unit + BASELINE * size, mCut);
    }
    canvas.restoreToCount(layer);
  }

  @Override
  protected void onBoundsChange(@NonNull Rect bounds)
  {
    mIcon.setBounds(bounds);
  }

  @Override
  public int getIntrinsicWidth()
  {
    return mIcon.getIntrinsicWidth();
  }

  @Override
  public int getIntrinsicHeight()
  {
    return mIcon.getIntrinsicHeight();
  }

  @Override
  public void setAlpha(int alpha)
  {
    mIcon.setAlpha(alpha);
    invalidateSelf();
  }

  @Override
  public void setColorFilter(@Nullable ColorFilter colorFilter)
  {
    mIcon.setColorFilter(colorFilter);
    invalidateSelf();
  }

  // setTint() comes here too.
  @Override
  public void setTintList(@Nullable ColorStateList tint)
  {
    mIcon.setTintList(tint);
    invalidateSelf();
  }

  @Override
  public void setTintMode(@Nullable PorterDuff.Mode tintMode)
  {
    mIcon.setTintMode(tintMode);
    invalidateSelf();
  }

  @Override
  public boolean isStateful()
  {
    return mIcon.isStateful();
  }

  @Override
  protected boolean onStateChange(@NonNull int[] state)
  {
    final boolean changed = mIcon.setState(state);
    if (changed)
      invalidateSelf();
    return changed;
  }

  @Override
  public int getOpacity()
  {
    return PixelFormat.TRANSLUCENT;
  }
}
