// Live location (NLL): the native side of app.organicmaps.sdk.livelocation (docs/LIVE_LOCATION.md §8.1).
// The core runs on a thread of its own. Java calls in on the main thread: calls with a result wait for
// it, the others are only queued, so that a busy core never blocks the UI for them. The core's events
// go back to LiveLocation.onEvent() as JSON, and positions to the map's marks on the GUI thread. Relay
// connections are OkHttp's, the store's wrapping keys the Android Keystore's.

#include "app/organicmaps/sdk/Framework.hpp"
#include "app/organicmaps/sdk/core/jni_helper.hpp"

#include "map/live_location_marks.hpp"

#include "live_location/crypto/random.hpp"
#include "live_location/encoding/utf16.hpp"
#include "live_location/manager/manager.hpp"
#include "live_location/manager/views_json.hpp"
#include "live_location/store/store.hpp"
#include "live_location/thread_executor.hpp"

#include "platform/platform.hpp"

#include "base/string_utils.hpp"

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace live_location_jni
{
using namespace live_location;

int64_t constexpr kRetireCheckMs = 500;
int64_t constexpr kRetireWaitMs = 30'000;  // at most, for the relays' answers to a stop
// Messages of one relay connection waiting for the core's thread. Normal traffic stays far below; a
// relay that floods the app loses the excess, and the relay pool fails it for the junk it reads.
size_t constexpr kMaxPendingMessages = 256;

// Made on the first nativeStart() or nativeRatchet(), on a Java thread, where the app's class loader
// finds the classes.
jclass g_transportClass;
jmethodID g_connect;
jmethodID g_send;
jmethodID g_close;
jclass g_keysClass;
jmethodID g_wrap;
jmethodID g_unwrap;
jmethodID g_deleteAllExcept;
jclass g_liveLocationClass;
jmethodID g_onEvent;
jmethodID g_onDotTapped;

void InitJniOnce(JNIEnv * env)
{
  g_transportClass = jni::GetGlobalClassRef(env, "app/organicmaps/sdk/livelocation/OkHttpTransport");
  g_connect = jni::GetStaticMethodID(env, g_transportClass, "connect", "(JLjava/lang/String;)V");
  g_send = jni::GetStaticMethodID(env, g_transportClass, "send", "(JLjava/lang/String;)V");
  g_close = jni::GetStaticMethodID(env, g_transportClass, "close", "(J)V");
  g_keysClass = jni::GetGlobalClassRef(env, "app/organicmaps/sdk/livelocation/KeystoreKeyWrapper");
  g_wrap = jni::GetStaticMethodID(env, g_keysClass, "wrap", "([B)[Ljava/lang/Object;");
  g_unwrap = jni::GetStaticMethodID(env, g_keysClass, "unwrap", "(Ljava/lang/String;[B)[B");
  g_deleteAllExcept = jni::GetStaticMethodID(env, g_keysClass, "deleteAllExcept", "(Ljava/lang/String;)V");
  g_liveLocationClass = jni::GetGlobalClassRef(env, "app/organicmaps/sdk/livelocation/LiveLocation");
  g_onEvent = jni::GetStaticMethodID(env, g_liveLocationClass, "onEvent", "(Ljava/lang/String;)V");
  g_onDotTapped = jni::GetStaticMethodID(env, g_liveLocationClass, "onDotTapped", "(Ljava/lang/String;)V");
}

std::once_flag g_jniOnce;

void InitJni(JNIEnv * env)
{
  // Once, whichever thread comes first: the app's main thread, or a background job's (D16).
  std::call_once(g_jniOnce, [env] { InitJniOnce(env); });
}

// Java strings are UTF-16, and JNI's own UTF-8 is "modified": both ways go through UTF-16.
std::string ToUtf8(JNIEnv * env, jstring str)
{
  if (str == nullptr)
    return {};
  jsize const length = env->GetStringLength(str);
  std::u16string utf16(static_cast<size_t>(length), u'\0');
  env->GetStringRegion(str, 0, length, reinterpret_cast<jchar *>(utf16.data()));
  return encoding::Utf16ToUtf8(utf16);
}

jstring ToJava(JNIEnv * env, std::string const & utf8)
{
  std::u16string const utf16 = strings::ToUtf16(utf8);
  return env->NewString(reinterpret_cast<jchar const *>(utf16.data()), static_cast<jsize>(utf16.size()));
}

Bytes ToBytes(JNIEnv * env, jbyteArray array)
{
  Bytes out(static_cast<size_t>(env->GetArrayLength(array)));
  env->GetByteArrayRegion(array, 0, static_cast<jsize>(out.size()), reinterpret_cast<jbyte *>(out.data()));
  return out;
}

jbyteArray ToJavaBytes(JNIEnv * env, ByteSpan bytes)
{
  jbyteArray out = env->NewByteArray(static_cast<jsize>(bytes.size()));
  if (out != nullptr)
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(bytes.size()), reinterpret_cast<jbyte const *>(bytes.data()));
  return out;
}

/// Sockets are OkHttp's (OkHttpTransport.java), named by ids of ours. Their events come in on OkHttp's
/// threads and are moved to the core's thread; those of a socket closed meanwhile are dropped.
class JavaTransport : public relay::Transport
{
public:
  explicit JavaTransport(Executor & executor) : m_executor(executor) {}

  /// On OkHttp's thread: queues a message for the core, unless too many of this socket's wait already.
  void Receive(int64_t id, std::string text)
  {
    {
      std::lock_guard lock(m_pendingMutex);
      size_t & pending = m_pending[id];
      if (pending >= kMaxPendingMessages)
        return;
      ++pending;
    }
    m_executor.Post([this, id, text = std::move(text)]
    {
      {
        std::lock_guard lock(m_pendingMutex);
        auto const it = m_pending.find(id);
        if (it != m_pending.end() && --it->second == 0)
          m_pending.erase(it);
      }
      OnMessage(id, text);
    });
  }

  std::unique_ptr<relay::Socket> Connect(std::string const & url, relay::SocketListener & listener) override
  {
    int64_t const id = m_nextId++;
    m_listeners[id] = &listener;
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalRef const jurl(env, ToJava(env, url));
    env->CallStaticVoidMethod(g_transportClass, g_connect, static_cast<jlong>(id), jurl.get());
    if (jni::HandleJavaException(env))
      m_executor.Post([this, id] { OnClosed(id, "cannot connect"); });
    return std::make_unique<JavaSocket>(*this, id);
  }

  // On the core's thread.
  void OnOpen(int64_t id)
  {
    if (auto * listener = Find(id))
      listener->OnOpen();
  }

  void OnMessage(int64_t id, std::string const & text)
  {
    if (auto * listener = Find(id))
      listener->OnMessage(text);
  }

  void OnClosed(int64_t id, std::string const & reason)
  {
    auto * listener = Find(id);
    if (listener == nullptr)
      return;
    m_listeners.erase(id);
    listener->OnClosed(reason);
  }

private:
  class JavaSocket : public relay::Socket
  {
  public:
    JavaSocket(JavaTransport & transport, int64_t id) : m_transport(transport), m_id(id) {}
    ~JavaSocket() override { m_transport.Close(m_id); }

    void Send(std::string const & text) override { m_transport.Send(m_id, text); }
    void Close() override { m_transport.Close(m_id); }

  private:
    JavaTransport & m_transport;
    int64_t const m_id;
  };

  relay::SocketListener * Find(int64_t id) const
  {
    auto const it = m_listeners.find(id);
    return it == m_listeners.end() ? nullptr : it->second;
  }

  void Send(int64_t id, std::string const & text)
  {
    if (Find(id) == nullptr)
      return;
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalRef const jtext(env, ToJava(env, text));
    env->CallStaticVoidMethod(g_transportClass, g_send, static_cast<jlong>(id), jtext.get());
    jni::HandleJavaException(env);
  }

  void Close(int64_t id)
  {
    if (m_listeners.erase(id) == 0)
      return;  // closed already, or by the relay: OkHttp has forgotten it too
    JNIEnv * env = jni::GetEnv();
    env->CallStaticVoidMethod(g_transportClass, g_close, static_cast<jlong>(id));
    jni::HandleJavaException(env);
  }

  Executor & m_executor;
  int64_t m_nextId = 1;
  std::map<int64_t, relay::SocketListener *> m_listeners;
  std::mutex m_pendingMutex;
  std::map<int64_t, size_t> m_pending;  // per socket, messages queued for the core's thread
};

/// The store's data key, wrapped by an Android Keystore key (KeystoreKeyWrapper.java). The Java arrays
/// that hold the data key are zeroed.
class JavaKeyWrapper : public store::KeyWrapper
{
public:
  std::optional<Wrapped> Wrap(Key const & dataKey) override
  {
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalByteArrayRef const key(env, ToJavaBytes(env, dataKey));
    if (key.get() == nullptr)
    {
      jni::HandleJavaException(env);
      return {};
    }
    // wrap() zeroes the array.
    jni::TScopedLocalObjectArrayRef const result(
        env, static_cast<jobjectArray>(env->CallStaticObjectMethod(g_keysClass, g_wrap, key.get())));
    if (jni::HandleJavaException(env) || result.get() == nullptr)
      return {};
    jni::TScopedLocalRef const alias(env, env->GetObjectArrayElement(result.get(), 0));
    jni::TScopedLocalRef const blob(env, env->GetObjectArrayElement(result.get(), 1));
    if (alias.get() == nullptr || blob.get() == nullptr)
      return {};
    Wrapped out;
    out.m_alias = ToUtf8(env, static_cast<jstring>(alias.get()));
    out.m_blob = ToBytes(env, static_cast<jbyteArray>(blob.get()));
    return out;
  }

  std::optional<Key> Unwrap(Wrapped const & wrapped) override
  {
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalRef const alias(env, ToJava(env, wrapped.m_alias));
    jni::TScopedLocalByteArrayRef const blob(env, ToJavaBytes(env, wrapped.m_blob));
    if (blob.get() == nullptr)
    {
      jni::HandleJavaException(env);
      return {};
    }
    jni::TScopedLocalByteArrayRef const key(
        env, static_cast<jbyteArray>(env->CallStaticObjectMethod(g_keysClass, g_unwrap, alias.get(), blob.get())));
    if (jni::HandleJavaException(env) || key.get() == nullptr)
      return {};
    jsize const size = env->GetArrayLength(key.get());
    Key out;
    bool const ok = size == static_cast<jsize>(out.size());
    if (ok)
      env->GetByteArrayRegion(key.get(), 0, size, reinterpret_cast<jbyte *>(out.data()));
    std::vector<jbyte> const zeros(static_cast<size_t>(size), 0);
    env->SetByteArrayRegion(key.get(), 0, size, zeros.data());
    if (!ok)
      return {};
    return out;
  }

  void DeleteAllExcept(std::string const & keep) override
  {
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalRef const jkeep(env, ToJava(env, keep));
    env->CallStaticVoidMethod(g_keysClass, g_deleteAllExcept, jkeep.get());
    jni::HandleJavaException(env);
  }
};

/// Contacts' positions on the map, on the GUI thread.
void ShowOnMap(std::vector<PositionInfo> positions)
{
  GetPlatform().RunTask(Platform::Thread::Gui, [positions = std::move(positions)]
  {
    static std::unique_ptr<LiveLocationMarks> marks;
    static ::Framework * owner = nullptr;
    if (!g_framework)
      return;
    ::Framework * const framework = frm();
    if (!marks || owner != framework)
    {
      marks = std::make_unique<LiveLocationMarks>(framework->GetBookmarkManager());
      owner = framework;
      // A tap on a dot opens the app's sheet for that contact (design doc §11.4), not a place page.
      framework->SetLiveLocationTapListener([](std::string const & contactId)
      {
        JNIEnv * env = jni::GetEnv();
        jni::TScopedLocalRef const jid(env, ToJava(env, contactId));
        env->CallStaticVoidMethod(g_liveLocationClass, g_onDotTapped, jid.get());
        jni::HandleJavaException(env);
      });
    }
    marks->Show(positions);
  });
}

/// The core: made on the first start, then kept for the life of the process, since OkHttp's callbacks
/// may come at any time. Stopping frees the manager and its store, once a stop has reached the relays.
class Host : public ManagerListener
{
public:
  Host() : m_transport(m_executor) {}

  ThreadExecutor & GetExecutor() { return m_executor; }
  JavaTransport & GetTransport() { return m_transport; }

  /// Runs `fn` with the manager on its thread, and waits. Nothing without a manager.
  template <typename Fn>
  void Run(Fn && fn)
  {
    m_executor.RunSync([&]
    {
      if (m_manager)
        fn(*m_manager);
    });
  }

  /// Runs `fn` with the manager on its thread, after what is queued already, without waiting.
  template <typename Fn>
  void Post(Fn && fn)
  {
    m_executor.Post([this, fn = std::forward<Fn>(fn)]() mutable
    {
      if (m_manager)
        fn(*m_manager);
    });
  }

  bool Start(std::string const & path)
  {
    bool ok = false;
    m_executor.RunSync([&]
    {
      ++m_generation;  // a stop still waiting for the relays is called off: the manager carries on
      if (!m_manager)
      {
        m_store = std::make_unique<store::Store>(path, m_keys, crypto::SystemRng());
        m_manager = std::make_unique<Manager>(m_executor, m_transport, *m_store, crypto::SystemRng(), *this);
        m_started = m_manager->Start();
      }
      ok = m_started;
      m_running = true;
      // Java starts with nothing: everything it shows.
      OnContacts(m_manager->Contacts());
      OnSharing(m_manager->Sharing());
      OnPositions(m_manager->Positions());
      for (auto const & pairing : m_manager->Pairings())
        OnPairing(pairing);
    });
    return ok;
  }

  /// Stops any share and the connections for viewing; the manager goes once the relays have answered.
  void Stop()
  {
    m_executor.RunSync([&]
    {
      m_running = false;
      ShowOnMap({});
      if (!m_manager)
        return;
      m_manager->SetForeground(false);
      m_manager->StopSharing();
      RetireWhenIdle(++m_generation, m_executor.NowMs() + kRetireWaitMs);
    });
  }

  /// D16: while the core does not run, its store is read, which erases the channel keys that are due
  /// and rotates the store's keys, and written; then everything is freed again. Nothing connects: the
  /// app is neither in the foreground nor sharing. While the core runs, its clock does this on time.
  void Ratchet(std::string const & path)
  {
    m_executor.RunSync([&]
    {
      if (m_manager)
        return;
      ManagerListener quiet;
      store::Store store(path, m_keys, crypto::SystemRng());
      Manager manager(m_executor, m_transport, store, crypto::SystemRng(), quiet);
      manager.Start();
    });
  }

  /// Also the way out of a store that cannot be read: the manager starts afresh.
  void DeleteAllData()
  {
    m_executor.RunSync([&]
    {
      if (!m_manager)
        return;
      m_manager->DeleteAllData();
      m_started = true;
    });
  }

  // ManagerListener, on the core's thread.
  void OnContacts(std::vector<ContactInfo> const & contacts) override { Send(ContactsJson(contacts)); }
  void OnPairing(PairingInfo const & pairing) override { Send(PairingJson(pairing)); }
  void OnPositions(std::vector<PositionInfo> const & positions) override
  {
    Send(PositionsJson(positions));
    if (m_running)
      ShowOnMap(positions);
  }
  void OnSharing(SharingInfo const & sharing) override { Send(SharingJson(sharing)); }
  void OnConsentNeeded(ConsentRequest const & request) override { Send(ConsentJson(request)); }
  void OnLocationRequest(LocationRequest request) override { Send(LocationRequestJson(request)); }
  void OnStoreError() override
  {
    auto event = json::Value::Object();
    event.Set("event", json::Value::String("store_error"));
    Send(event);
  }

private:
  void Send(json::Value const & event)
  {
    JNIEnv * env = jni::GetEnv();
    jni::TScopedLocalRef const json(env, ToJava(env, event.Dump()));
    env->CallStaticVoidMethod(g_liveLocationClass, g_onEvent, json.get());
    jni::HandleJavaException(env);
  }

  void RetireWhenIdle(uint64_t generation, int64_t deadlineMs)
  {
    m_executor.PostDelayed(kRetireCheckMs, [this, generation, deadlineMs]
    {
      if (generation != m_generation || !m_manager)
        return;
      if (m_manager->HasPendingPublications() && m_executor.NowMs() < deadlineMs)
        return RetireWhenIdle(generation, deadlineMs);
      m_manager.reset();
      m_store.reset();
    });
  }

  ThreadExecutor m_executor;
  JavaTransport m_transport;
  JavaKeyWrapper m_keys;
  std::unique_ptr<store::Store> m_store;
  std::unique_ptr<Manager> m_manager;
  bool m_started = false;     // the store was read
  bool m_running = false;     // between a start and a stop
  uint64_t m_generation = 0;  // a new one on each start and stop
};

std::atomic<Host *> g_host{nullptr};

/// The process's host, made by whichever thread needs it first.
Host * GetOrMakeHost()
{
  Host * host = g_host.load();
  if (host != nullptr)
    return host;
  auto * made = new Host();
  if (g_host.compare_exchange_strong(host, made))
    return made;
  delete made;  // another thread made one meanwhile
  return host;
}

/// `fn` with the manager on its thread; nothing when the feature has not started.
template <typename Fn>
void Run(Fn && fn)
{
  if (Host * host = g_host.load())
    host->Run(std::forward<Fn>(fn));
}

/// The same for calls without a result: queued, without waiting.
template <typename Fn>
void Post(Fn && fn)
{
  if (Host * host = g_host.load())
    host->Post(std::forward<Fn>(fn));
}

std::optional<std::string> PairingResult(std::optional<PairingInfo> const & pairing)
{
  if (!pairing)
    return {};
  return PairingJson(*pairing).Dump();
}

std::optional<Manager::Recipients> ToRecipients(JNIEnv * env, jobjectArray ids, jlongArray untils)
{
  jsize const count = env->GetArrayLength(ids);
  if (env->GetArrayLength(untils) != count)
    return {};
  std::vector<jlong> until(static_cast<size_t>(count));
  env->GetLongArrayRegion(untils, 0, count, until.data());
  Manager::Recipients out;
  for (jsize i = 0; i < count; ++i)
  {
    jni::TScopedLocalRef const id(env, env->GetObjectArrayElement(ids, i));
    out.emplace_back(ToUtf8(env, static_cast<jstring>(id.get())), static_cast<int64_t>(until[i]));
  }
  return out;
}

// The JNI entry points: C names, so the namespace only keeps this file's names to itself (unity builds).
extern "C"
{
// --- app.organicmaps.sdk.livelocation.LiveLocation ----------------------------------------------------

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeStart(JNIEnv * env, jclass,
                                                                                          jstring path)
{
  InitJni(env);
  return GetOrMakeHost()->Start(ToUtf8(env, path));
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeRatchet(JNIEnv * env, jclass,
                                                                                        jstring path)
{
  InitJni(env);
  GetOrMakeHost()->Ratchet(ToUtf8(env, path));
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeStop(JNIEnv *, jclass)
{
  if (Host * host = g_host.load())
    host->Stop();
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeDeleteAllData(JNIEnv *, jclass)
{
  if (Host * host = g_host.load())
    host->DeleteAllData();
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetForeground(JNIEnv *, jclass,
                                                                                              jboolean foreground)
{
  Post([foreground](Manager & manager) { manager.SetForeground(foreground); });
}

JNIEXPORT jstring JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeGetSettings(JNIEnv * env, jclass)
{
  std::string settings = "{}";
  Run([&settings](Manager & manager) { settings = SettingsJson(manager.GetSettings(), manager.IsStarted()).Dump(); });
  return ToJava(env, settings);
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetName(JNIEnv * env, jclass,
                                                                                            jstring name)
{
  bool ok = false;
  Run([&ok, n = ToUtf8(env, name)](Manager & manager) mutable { ok = manager.SetName(std::move(n)); });
  return ok;
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetHomeRelays(JNIEnv * env, jclass,
                                                                                                  jobjectArray relays)
{
  Relays urls;
  jsize const count = env->GetArrayLength(relays);
  for (jsize i = 0; i < count; ++i)
  {
    jni::TScopedLocalRef const url(env, env->GetObjectArrayElement(relays, i));
    urls.push_back(ToUtf8(env, static_cast<jstring>(url.get())));
  }
  bool ok = false;
  Run([&ok, &urls](Manager & manager) { ok = manager.SetHomeRelays(std::move(urls)); });
  return ok;
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetConsent(JNIEnv * env, jclass,
                                                                                           jstring url, jint answer,
                                                                                           jstring forContact)
{
  // LiveLocationModels.Consent's ordinals.
  Consent const consent = answer == 0 ? Consent::Allow : answer == 1 ? Consent::NotNow : Consent::Refuse;
  Post([u = ToUtf8(env, url), consent, c = ToUtf8(env, forContact)](Manager & manager)
  { manager.SetConsent(u, consent, c); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeRevokeConsent(JNIEnv * env, jclass,
                                                                                              jstring url)
{
  Post([u = ToUtf8(env, url)](Manager & manager) { manager.RevokeConsent(u); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetRequestLive(JNIEnv *, jclass,
                                                                                               jboolean request)
{
  Post([request](Manager & manager) { manager.SetRequestLive(request); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetAllowLive(JNIEnv *, jclass,
                                                                                             jboolean allow)
{
  Post([allow](Manager & manager) { manager.SetAllowLive(allow); });
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetColor(JNIEnv * env, jclass,
                                                                                             jstring color)
{
  bool ok = false;
  Run([&ok, c = ToUtf8(env, color)](Manager & manager) mutable { ok = manager.SetColor(std::move(c)); });
  return ok;
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetLowBatteryStop(JNIEnv *, jclass,
                                                                                                      jint percent)
{
  bool ok = false;
  Run([&ok, percent](Manager & manager) { ok = manager.SetLowBatteryStop(percent); });
  return ok;
}

JNIEXPORT jstring JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeCreateInvite(JNIEnv * env, jclass,
                                                                                                jboolean byLink)
{
  std::optional<std::string> result;
  Run([&result, byLink](Manager & manager) { result = PairingResult(manager.CreateInvite(byLink)); });
  return result ? ToJava(env, *result) : nullptr;
}

JNIEXPORT jstring JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeOpenInvite(JNIEnv * env, jclass,
                                                                                              jstring link)
{
  std::optional<std::string> result;
  Run([&result, l = ToUtf8(env, link)](Manager & manager) { result = PairingResult(manager.OpenInvite(l)); });
  return result ? ToJava(env, *result) : nullptr;
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeConfirmCode(JNIEnv * env, jclass,
                                                                                            jstring pairingId,
                                                                                            jboolean match)
{
  Post([id = ToUtf8(env, pairingId), match](Manager & manager) { manager.ConfirmCode(id, match); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeDecide(JNIEnv * env, jclass,
                                                                                       jstring pairingId,
                                                                                       jboolean accept,
                                                                                       jboolean compared)
{
  Post([id = ToUtf8(env, pairingId), accept, compared](Manager & manager) { manager.Decide(id, accept, compared); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeCancelPairing(JNIEnv * env, jclass,
                                                                                              jstring pairingId)
{
  Post([id = ToUtf8(env, pairingId)](Manager & manager) { manager.CancelPairing(id); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeRenameContact(JNIEnv * env, jclass,
                                                                                              jstring id, jstring name)
{
  Post([i = ToUtf8(env, id), n = ToUtf8(env, name)](Manager & manager) mutable
  { manager.RenameContact(i, std::move(n)); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeDeleteContact(JNIEnv * env, jclass,
                                                                                              jstring id)
{
  Post([i = ToUtf8(env, id)](Manager & manager) { manager.DeleteContact(i); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeMarkVerified(JNIEnv * env, jclass,
                                                                                             jstring id)
{
  Post([i = ToUtf8(env, id)](Manager & manager) { manager.MarkVerified(i); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeSetHidden(JNIEnv * env, jclass,
                                                                                          jstring id, jboolean hidden)
{
  Post([i = ToUtf8(env, id), hidden](Manager & manager) { manager.SetHidden(i, hidden); });
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeStartSharing(JNIEnv * env, jclass,
                                                                                                 jobjectArray ids,
                                                                                                 jlongArray untils)
{
  auto const recipients = ToRecipients(env, ids, untils);
  bool ok = false;
  if (recipients)
    Run([&ok, &recipients](Manager & manager) { ok = manager.StartSharing(*recipients); });
  return ok;
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeChangeSharing(JNIEnv * env, jclass,
                                                                                                  jobjectArray ids,
                                                                                                  jlongArray untils)
{
  auto const recipients = ToRecipients(env, ids, untils);
  bool ok = false;
  if (recipients)
    Run([&ok, &recipients](Manager & manager) { ok = manager.ChangeSharing(*recipients); });
  return ok;
}

JNIEXPORT jboolean JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeExtendSharing(JNIEnv * env, jclass,
                                                                                                  jstring id,
                                                                                                  jlong until)
{
  bool ok = false;
  Run([&ok, i = ToUtf8(env, id), until](Manager & manager) { ok = manager.ExtendSharing(i, until); });
  return ok;
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeStopSharing(JNIEnv *, jclass)
{
  Post([](Manager & manager) { manager.StopSharing(); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeDismissResume(JNIEnv *, jclass)
{
  Post([](Manager & manager) { manager.DismissResume(); });
}

// Unknown speed and bearing are negative. Never a NaN: this file is built with -ffast-math, and the
// manager checks every value again (Manager::OnLocation).
JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeOnLocation(
    JNIEnv *, jclass, jdouble lat, jdouble lon, jdouble accuracy, jdouble speed, jdouble bearing, jboolean hasAltitude,
    jdouble altitude, jlong timeMs)
{
  Location fix;
  fix.m_ts = timeMs;
  fix.m_lat = lat;
  fix.m_lon = lon;
  fix.m_acc = accuracy;
  if (speed >= 0)
    fix.m_spd = speed;
  if (bearing >= 0)
    fix.m_brg = bearing;
  if (hasAltitude)
    fix.m_alt = altitude;
  Post([fix](Manager & manager) { manager.OnLocation(fix); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_LiveLocation_nativeOnBatteryLevel(JNIEnv *, jclass,
                                                                                               jint percent)
{
  Post([percent](Manager & manager) { manager.OnBatteryLevel(percent); });
}

// --- app.organicmaps.sdk.livelocation.OkHttpTransport, on OkHttp's threads --------------------------

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_OkHttpTransport_nativeOnOpen(JNIEnv *, jclass, jlong id)
{
  if (Host * host = g_host.load())
    host->GetExecutor().Post([host, id] { host->GetTransport().OnOpen(id); });
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_OkHttpTransport_nativeOnMessage(JNIEnv * env, jclass,
                                                                                             jlong id, jstring text)
{
  if (Host * host = g_host.load())
    host->GetTransport().Receive(id, ToUtf8(env, text));
}

JNIEXPORT void JNICALL Java_app_organicmaps_sdk_livelocation_OkHttpTransport_nativeOnClosed(JNIEnv * env, jclass,
                                                                                            jlong id, jstring reason)
{
  if (Host * host = g_host.load())
    host->GetExecutor().Post([host, id, r = ToUtf8(env, reason)] { host->GetTransport().OnClosed(id, r); });
}
}  // extern "C"
}  // namespace live_location_jni
