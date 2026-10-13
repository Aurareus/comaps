package app.organicmaps.sdk.livelocation;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

/**
 * Live location (NLL): the WebSocket connections to relays, for the native relay pool
 * (docs/LIVE_LOCATION.md §8.1, D7). TLS and its certificate store are the platform's, through
 * OkHttp. No client pings: they would wake the radio (D17); a missing OK tells the native side that
 * a connection died.
 *
 * <p>Every connection gets a TLS context of its own. With a shared one, TLS sessions would be
 * resumed across connections, and the session ticket would let a relay link connections that the
 * design keeps apart, such as two days' connections or a pairing's (spec §11, "whatever the IP
 * address").
 *
 * <p>Native code opens, sends to and closes sockets by an id of its own. OkHttp's callbacks come
 * back on OkHttp's threads; the native side moves them to its own thread and ignores those for
 * sockets it has closed.
 */
@Keep
public final class OkHttpTransport
{
  private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
                                                 .connectTimeout(15, TimeUnit.SECONDS)
                                                 .readTimeout(0, TimeUnit.SECONDS)
                                                 .writeTimeout(15, TimeUnit.SECONDS)
                                                 .pingInterval(0, TimeUnit.SECONDS)
                                                 .retryOnConnectionFailure(false)
                                                 .build();
  private static final Map<Long, WebSocket> SOCKETS = new ConcurrentHashMap<>();
  // The core reads relay messages of up to 64 KiB; longer ones are not even copied to it.
  private static final int MAX_MESSAGE_CHARS = 64 * 1024;
  @Nullable
  private static X509TrustManager sTrustManager;

  private OkHttpTransport() {}

  @SuppressWarnings("unused")
  public static void connect(long id, @NonNull String url)
  {
    final Request request;
    final OkHttpClient client;
    try
    {
      request = new Request.Builder().url(url).build();
      client = clientForOneConnection();
    }
    catch (IllegalArgumentException e)
    {
      nativeOnClosed(id, "invalid URL");
      return;
    }
    catch (GeneralSecurityException e)
    {
      nativeOnClosed(id, "TLS: " + e.getClass().getSimpleName());
      return;
    }
    SOCKETS.put(id, client.newWebSocket(request, new WebSocketListener() {
      @Override
      public void onOpen(@NonNull WebSocket webSocket, @NonNull Response response)
      {
        nativeOnOpen(id);
      }

      @Override
      public void onMessage(@NonNull WebSocket webSocket, @NonNull String text)
      {
        if (text.length() <= MAX_MESSAGE_CHARS)
          nativeOnMessage(id, text);
      }

      @Override
      public void onClosing(@NonNull WebSocket webSocket, int code, @NonNull String reason)
      {
        webSocket.close(1000, null);
      }

      @Override
      public void onClosed(@NonNull WebSocket webSocket, int code, @NonNull String reason)
      {
        SOCKETS.remove(id);
        nativeOnClosed(id, "closed: " + code);
      }

      @Override
      public void onFailure(@NonNull WebSocket webSocket, @NonNull Throwable t, @Nullable Response response)
      {
        SOCKETS.remove(id);
        nativeOnClosed(id, t.getClass().getSimpleName());
      }
    }));
  }

  /** The shared client with a new TLS context: nothing of an earlier connection's TLS session to resume. */
  @NonNull
  private static OkHttpClient clientForOneConnection() throws GeneralSecurityException
  {
    final X509TrustManager trustManager = platformTrustManager();
    final SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, new TrustManager[] {trustManager}, null);
    return CLIENT.newBuilder().sslSocketFactory(context.getSocketFactory(), trustManager).build();
  }

  /** The platform's certificate store, with the app's network security configuration. */
  @NonNull
  private static synchronized X509TrustManager platformTrustManager() throws GeneralSecurityException
  {
    if (sTrustManager == null)
    {
      final TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      factory.init((KeyStore) null);
      for (TrustManager manager : factory.getTrustManagers())
        if (manager instanceof X509TrustManager)
          sTrustManager = (X509TrustManager) manager;
      if (sTrustManager == null)
        throw new GeneralSecurityException("no X509TrustManager");
    }
    return sTrustManager;
  }

  @SuppressWarnings("unused")
  public static void send(long id, @NonNull String text)
  {
    final WebSocket socket = SOCKETS.get(id);
    if (socket != null)
      socket.send(text);
  }

  @SuppressWarnings("unused")
  public static void close(long id)
  {
    final WebSocket socket = SOCKETS.remove(id);
    if (socket != null)
      socket.close(1000, null);
  }

  private static native void nativeOnOpen(long id);
  private static native void nativeOnMessage(long id, @NonNull String text);
  private static native void nativeOnClosed(long id, @NonNull String reason);
}
