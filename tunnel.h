#pragma once

#include "stream.h"
#include "log.h"
#include "uvw/tcp.h"

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

#include <uvw.hpp>

namespace tunnel {

// The server sends back a 0x00 to signal that the remote TCP connection was established and that it
// is now accepting stream data; the client is not allowed to send any other data down the stream
// until this comes back (any data sent down the stream before then is discarded.)
inline constexpr std::byte CONNECT_INIT{0x00};
// QUIC application error codes we sent on failures:
// Failure to establish an initial connection:
inline constexpr uint64_t ERROR_CONNECT{0x5471907};
// Error if we receive something other than CONNECT_INIT as the initial stream data from the server
inline constexpr uint64_t ERROR_BAD_INIT{0x5471908};
// Close error code sent if we get an error on the TCP socket (other than an initial connect
// failure)
inline constexpr uint64_t ERROR_TCP{0x5471909};

// Callbacks for network events.  The uvw::TCPHandle client must contain a shared pointer to the
// associated quic::Stream in its data, and the quic::Stream must contain a weak pointer to the
// uvw::TCPHandle.

// Callback when we receive data to go out over lokinet, i.e. read from the local TCP socket
void on_outgoing_data(uvw::DataEvent& event, uvw::TCPHandle& client);

// Callback when we receive data from lokinet to write to the local TCP socket
void on_incoming_data(quic::Stream& stream, quic::bstring_view bdata);

// Callback to handle and discard the first incoming 0x00 byte that initiates the stream
void on_init_incoming_data(quic::Stream& stream, quic::bstring_view bdata);

// Creates a new tcp handle that forwards incoming data/errors/closes into appropriate actions on
// the given quic stream.
void install_stream_forwarding(uvw::TCPHandle& tcp, quic::Stream& stream);

template <typename Int>
bool parse_int(std::string_view arg, Int& i) {
    const char* begin = arg.data();
    const char* end = begin + arg.size();
    auto [p, ec] = std::from_chars(begin, end, i);
    return ec == std::errc{} && p == end;
}

}
