package app.organicmaps.sdk.livelocation;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
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

  private OkHttpTransport() {}

  @SuppressWarnings("unused")
  public static void connect(long id, @NonNull String url)
  {
    final Request request;
    try
    {
      request = new Request.Builder().url(url).build();
    }
    catch (IllegalArgumentException e)
    {
      nativeOnClosed(id, "invalid URL");
      return;
    }
    SOCKETS.put(id, CLIENT.newWebSocket(request, new WebSocketListener() {
      @Override
      public void onOpen(@NonNull WebSocket webSocket, @NonNull Response response)
      {
        nativeOnOpen(id);
      }

      @Override
      public void onMessage(@NonNull WebSocket webSocket, @NonNull String text)
      {
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
