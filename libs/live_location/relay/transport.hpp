#pragma once

#include <memory>
#include <string>

// The WebSocket client is the platform's (OkHttp on Android), as are TLS and its certificate store
// (design doc §8.1). The core sees this interface only.
namespace live_location::relay
{
/// Events of one connection. They arrive on the executor's thread, in order: OnOpen at most once, then
/// messages, then OnClosed exactly once, unless the socket was closed or destroyed first: after Close()
/// or the destruction of the socket, nothing more arrives.
class SocketListener
{
public:
  virtual ~SocketListener() = default;
  virtual void OnOpen() = 0;
  virtual void OnMessage(std::string const & text) = 0;
  /// Closed by the relay, or failed to connect or later. `reason` is for logs only.
  virtual void OnClosed(std::string const & reason) = 0;
};

/// One connection to one relay.
class Socket
{
public:
  virtual ~Socket() = default;
  /// Call on the executor's thread, after OnOpen.
  virtual void Send(std::string const & text) = 0;
  /// Closes the connection; no further events arrive. Call on the executor's thread.
  virtual void Close() = 0;
};

class Transport
{
public:
  virtual ~Transport() = default;
  /// Starts connecting to `url` (wss://, or ws:// to loopback). `listener` must outlive the socket.
  virtual std::unique_ptr<Socket> Connect(std::string const & url, SocketListener & listener) = 0;
};
}  // namespace live_location::relay
