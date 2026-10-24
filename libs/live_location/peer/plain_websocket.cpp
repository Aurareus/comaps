#include "live_location/peer/plain_websocket.hpp"

#include "live_location/crypto/bytes.hpp"
#include "live_location/encoding/base64.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <optional>
#include <random>
#include <thread>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace live_location::peer
{
namespace
{
size_t constexpr kMaxMessage = 1 << 20;

struct Url
{
  std::string m_host;
  std::string m_port = "80";
  std::string m_path = "/";
};

std::optional<Url> ParseUrl(std::string const & url)
{
  std::string_view constexpr kScheme = "ws://";
  if (url.rfind(kScheme, 0) != 0)
    return {};
  std::string rest = url.substr(kScheme.size());
  Url out;
  if (auto const slash = rest.find('/'); slash != std::string::npos)
  {
    out.m_path = rest.substr(slash);
    rest = rest.substr(0, slash);
  }
  if (!rest.empty() && rest.front() == '[')
  {
    auto const close = rest.find(']');
    if (close == std::string::npos)
      return {};
    out.m_host = rest.substr(1, close - 1);
    if (close + 1 < rest.size() && rest[close + 1] == ':')
      out.m_port = rest.substr(close + 2);
  }
  else if (auto const colon = rest.find(':'); colon != std::string::npos)
  {
    out.m_host = rest.substr(0, colon);
    out.m_port = rest.substr(colon + 1);
  }
  else
  {
    out.m_host = rest;
  }
  if (out.m_host.empty() || out.m_port.empty())
    return {};
  return out;
}

bool WriteAll(int fd, uint8_t const * data, size_t size)
{
  while (size > 0)
  {
    ssize_t const n = ::send(fd, data, size, MSG_NOSIGNAL);
    if (n <= 0)
      return false;
    data += n;
    size -= static_cast<size_t>(n);
  }
  return true;
}

bool ReadExact(int fd, uint8_t * data, size_t size)
{
  while (size > 0)
  {
    ssize_t const n = ::recv(fd, data, size, 0);
    if (n <= 0)
      return false;
    data += n;
    size -= static_cast<size_t>(n);
  }
  return true;
}

/// What the reader thread and the socket share. Only the executor's thread closes or destroys the
/// socket, and the events it posts check `m_closed` on that thread, so none arrives after Close().
struct Shared
{
  std::atomic<bool> m_closed = false;
  std::atomic<int> m_fd = -1;
  std::mutex m_write;
};

class PlainSocket : public relay::Socket
{
public:
  PlainSocket(Executor & executor, std::string url, relay::SocketListener & listener)
    : m_executor(executor)
    , m_listener(listener)
    , m_shared(std::make_shared<Shared>())
  {
    m_thread = std::thread([this, url = std::move(url)] { Run(url); });
  }

  ~PlainSocket() override
  {
    Close();
    if (m_thread.joinable())
      m_thread.join();
    if (int const fd = m_shared->m_fd.load(); fd >= 0)
      ::close(fd);
  }

  void Send(std::string const & text) override
  {
    if (!m_shared->m_closed)
      WriteFrame(0x1, AsBytes(text));
  }

  void Close() override
  {
    if (m_shared->m_closed.exchange(true))
      return;
    WriteFrame(0x8, {});  // best effort
    if (int const fd = m_shared->m_fd.load(); fd >= 0)
      ::shutdown(fd, SHUT_RDWR);  // wakes the reader thread; the destructor closes the descriptor
  }

private:
  void Post(std::function<void(relay::SocketListener &)> event)
  {
    auto shared = m_shared;
    relay::SocketListener * listener = &m_listener;
    m_executor.Post([shared, listener, event = std::move(event)]
    {
      if (!shared->m_closed)
        event(*listener);
    });
  }

  uint8_t RandomByte()
  {
    std::lock_guard lock(m_randomMutex);
    return static_cast<uint8_t>(m_random());
  }

  void Closed(std::string reason)
  {
    Post([reason = std::move(reason)](relay::SocketListener & l) { l.OnClosed(reason); });
  }

  void WriteFrame(uint8_t opcode, ByteSpan payload)
  {
    int const fd = m_shared->m_fd.load();
    if (fd < 0)
      return;
    Bytes frame = {static_cast<uint8_t>(0x80 | opcode)};  // FIN
    size_t const size = payload.size();
    if (size < 126)
    {
      frame.push_back(static_cast<uint8_t>(0x80 | size));  // masked, as clients must
    }
    else if (size <= 0xffff)
    {
      frame.insert(frame.end(), {uint8_t{0x80 | 126}, static_cast<uint8_t>(size >> 8), static_cast<uint8_t>(size)});
    }
    else
    {
      frame.push_back(0x80 | 127);
      for (int i = 7; i >= 0; --i)
        frame.push_back(static_cast<uint8_t>(static_cast<uint64_t>(size) >> (8 * i)));
    }
    uint8_t mask[4];
    for (auto & b : mask)
      b = RandomByte();
    frame.insert(frame.end(), mask, mask + 4);
    for (size_t i = 0; i < size; ++i)
      frame.push_back(payload[i] ^ mask[i % 4]);
    std::lock_guard lock(m_shared->m_write);
    WriteAll(fd, frame.data(), frame.size());
  }

  void Run(std::string const & url)
  {
    auto const parsed = ParseUrl(url);
    if (!parsed)
      return Closed("only ws:// URLs are supported here");

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo * addresses = nullptr;
    if (::getaddrinfo(parsed->m_host.c_str(), parsed->m_port.c_str(), &hints, &addresses) != 0)
      return Closed("unknown host");
    int fd = -1;
    for (addrinfo * a = addresses; a != nullptr && fd < 0; a = a->ai_next)
    {
      fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd >= 0 && ::connect(fd, a->ai_addr, a->ai_addrlen) != 0)
      {
        ::close(fd);
        fd = -1;
      }
    }
    ::freeaddrinfo(addresses);
    if (fd < 0)
      return Closed("connection refused");
    m_shared->m_fd = fd;
    if (m_shared->m_closed)
      return;

    // The handshake. Sec-WebSocket-Accept is not checked: a test tool talking to a local relay.
    uint8_t keyBytes[16];
    for (auto & b : keyBytes)
      b = RandomByte();
    std::string const request =
        "GET " + parsed->m_path + " HTTP/1.1\r\nHost: " + parsed->m_host + ":" + parsed->m_port +
        "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " +
        Base64Encode(ByteSpan(keyBytes, sizeof(keyBytes))) + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
    {
      std::lock_guard lock(m_shared->m_write);
      if (!WriteAll(fd, reinterpret_cast<uint8_t const *>(request.data()), request.size()))
        return Closed("handshake failed");
    }
    std::string response;
    uint8_t c;
    while (response.size() < 8192 && response.find("\r\n\r\n") == std::string::npos)
    {
      if (!ReadExact(fd, &c, 1))
        return Closed("handshake failed");
      response.push_back(static_cast<char>(c));
    }
    if (response.rfind("HTTP/1.1 101", 0) != 0)
      return Closed("handshake refused");
    Post([](relay::SocketListener & l) { l.OnOpen(); });

    std::string message;
    while (true)
    {
      uint8_t header[2];
      if (!ReadExact(fd, header, 2))
        break;
      bool const fin = (header[0] & 0x80) != 0;
      uint8_t const opcode = header[0] & 0x0f;
      bool const masked = (header[1] & 0x80) != 0;
      uint64_t size = header[1] & 0x7f;
      if (size == 126 || size == 127)
      {
        uint8_t extended[8];
        size_t const n = size == 126 ? 2 : 8;
        if (!ReadExact(fd, extended, n))
          break;
        size = 0;
        for (size_t i = 0; i < n; ++i)
          size = (size << 8) | extended[i];
      }
      uint8_t mask[4] = {};
      if (masked && !ReadExact(fd, mask, 4))
        break;
      if (size > kMaxMessage || message.size() + size > kMaxMessage)
        break;
      Bytes payload(size);
      if (size > 0 && !ReadExact(fd, payload.data(), size))
        break;
      if (masked)
        for (size_t i = 0; i < payload.size(); ++i)
          payload[i] ^= mask[i % 4];

      if (opcode == 0x9)
      {
        WriteFrame(0xA, payload);  // pong
      }
      else if (opcode == 0x8)
      {
        if (!m_shared->m_closed)
          WriteFrame(0x8, {});
        break;
      }
      else if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2)
      {
        message.append(payload.begin(), payload.end());
        if (fin)
        {
          Post([text = std::move(message)](relay::SocketListener & l) { l.OnMessage(text); });
          message.clear();
        }
      }
    }
    Closed("connection closed");
  }

  Executor & m_executor;
  relay::SocketListener & m_listener;
  std::shared_ptr<Shared> m_shared;
  std::mutex m_randomMutex;
  std::mt19937 m_random{std::random_device{}()};  // masking keys and the handshake key: not secrets
  std::thread m_thread;
};
}  // namespace

std::unique_ptr<relay::Socket> PlainTransport::Connect(std::string const & url, relay::SocketListener & listener)
{
  return std::make_unique<PlainSocket>(m_executor, url, listener);
}
}  // namespace live_location::peer
