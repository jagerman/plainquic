#pragma once

#include "stream.h"
#include "log.h"
#include "uvw/tcp.h"

#include <cstdint>
#include <string>
#include <string_view>

#include <uvw.hpp>

namespace tunnel {

enum class tunnel_error : uint64_t {
    TCP_NONE = 0,
    TCP_FAILED = 1,
    TCP_CLOSED = 2,
};

constexpr uint64_t code(tunnel_error e) { return static_cast<uint64_t>(e); }

constexpr std::string_view tunnel_error_str(tunnel_error code) {
    using namespace std::literals;
    switch (code) {
        case tunnel_error::TCP_NONE: return "(no error)"sv;
        case tunnel_error::TCP_FAILED: return "Remote TCP connection failed"sv;
        case tunnel_error::TCP_CLOSED: return "Remote TCP connection closed"sv;
        default: return "(unknown error)"sv;
    }
}

constexpr std::string_view tunnel_error_str(uint64_t code) {
    return tunnel_error_str(tunnel_error{code});
}

// Callbacks for network events.  The uvw::TCPHandle client must contain a shared pointer to the
// associated quic::Stream in its data, and the quic::Stream must contain a weak pointer to the
// uvw::TCPHandle.

// Callback when we receive data to go out over lokinet, i.e. read from the local TCP socket
void on_outgoing_data(const uvw::DataEvent& event, uvw::TCPHandle& client);

// Callback when we receive data from lokinet to write to the local TCP socket
void on_incoming_data(quic::Stream& stream, quic::bstring_view bdata);

// Callback when the stream closes; if the remote lokinet closed it then code will be set to the
// application error code it provided.
void on_remote_close(quic::Stream& s, std::optional<uint64_t> code);

// Creates a new tcp handle that forwards incoming data/errors/closes into appropriate actions on
// the given quic stream.
void install_stream_forwarding(uvw::TCPHandle& tcp, quic::Stream& stream);

}
