package app.organicmaps.sdk.livelocation;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import app.organicmaps.sdk.util.log.Logger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Live location (NLL): wraps the data key of the live location store with an Android Keystore
 * AES-256-GCM key (docs/LIVE_LOCATION.md §10.4). Every wrap makes a new Keystore key, so that
 * deleting the old one leaves old copies of the store unreadable. The keys need no user
 * authentication: sharing must work with the screen locked.
 *
 * <p>Called from native code on the live location thread. The data key passes through Java only
 * here, and the arrays holding it are zeroed.
 */
@Keep
public final class KeystoreKeyWrapper
{
  private static final String TAG = KeystoreKeyWrapper.class.getSimpleName();
  private static final String KEYSTORE = "AndroidKeyStore";
  private static final String PREFIX = "comaps-live-location-";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int TAG_BITS = 128;

  private KeystoreKeyWrapper() {}

  /** A new Keystore key, and {@code dataKey} encrypted under it: {alias, iv length || iv || ciphertext}. */
  @SuppressWarnings("unused")
  @Nullable
  public static Object[] wrap(@NonNull byte[] dataKey)
  {
    try
    {
      final byte[] name = new byte[16];
      new SecureRandom().nextBytes(name);
      final String alias = PREFIX + toHex(name);
      final KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
      generator.init(
          new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
              .setKeySize(256)
              .build());
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, generator.generateKey());
      final byte[] iv = cipher.getIV();
      final byte[] sealed = cipher.doFinal(dataKey);
      final byte[] blob = new byte[1 + iv.length + sealed.length];
      blob[0] = (byte) iv.length;
      System.arraycopy(iv, 0, blob, 1, iv.length);
      System.arraycopy(sealed, 0, blob, 1 + iv.length, sealed.length);
      return new Object[] {alias, blob};
    }
    catch (GeneralSecurityException | RuntimeException e)
    {
      Logger.e(TAG, "Cannot wrap the live location key", e);
      return null;
    }
    finally
    {
      Arrays.fill(dataKey, (byte) 0);
    }
  }

  /** The data key, or null when the Keystore key is gone or the blob does not open. */
  @SuppressWarnings("unused")
  @Nullable
  public static byte[] unwrap(@NonNull String alias, @NonNull byte[] blob)
  {
    try
    {
      final KeyStore store = KeyStore.getInstance(KEYSTORE);
      store.load(null);
      final Key key = store.getKey(alias, null);
      if (key == null || blob.length < 1)
        return null;
      final int ivLength = blob[0] & 0xff;
      if (blob.length < 1 + ivLength)
        return null;
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 1, ivLength));
      return cipher.doFinal(blob, 1 + ivLength, blob.length - 1 - ivLength);
    }
    catch (Exception e)
    {
      Logger.e(TAG, "Cannot unwrap the live location key", e);
      return null;
    }
  }

  /** Deletes every live location Keystore key but {@code keep}; all of them when it is empty. */
  @SuppressWarnings("unused")
  public static void deleteAllExcept(@NonNull String keep)
  {
    try
    {
      final KeyStore store = KeyStore.getInstance(KEYSTORE);
      store.load(null);
      final List<String> aliases = new ArrayList<>(Collections.list(store.aliases()));
      for (String alias : aliases)
      {
        if (alias.startsWith(PREFIX) && !alias.equals(keep))
          store.deleteEntry(alias);
      }
    }
    catch (Exception e)
    {
      Logger.e(TAG, "Cannot delete old live location keys", e);
    }
  }

  @NonNull
  private static String toHex(@NonNull byte[] bytes)
  {
    final StringBuilder out = new StringBuilder(bytes.length * 2);
    for (byte b : bytes)
      out.append(String.format("%02x", b & 0xff));
    return out.toString();
  }
}
