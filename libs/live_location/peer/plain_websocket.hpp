#pragma once

#include "live_location/executor.hpp"
#include "live_location/relay/transport.hpp"

#include <memory>
#include <string>

// A WebSocket client (RFC 6455) over plain TCP, for the desktop test peer: ws:// only, which spec §5
// allows for loopback relays. The app uses the platform's client, with TLS.
namespace live_location::peer
{
class PlainTransport : public relay::Transport
{
public:
  explicit PlainTransport(Executor & executor) : m_executor(executor) {}

  std::unique_ptr<relay::Socket> Connect(std::string const & url, relay::SocketListener & listener) override;

private:
  Executor & m_executor;
};
}  // namespace live_location::peer
