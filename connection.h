#pragma once

#include "address.h"
#include "random.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_set>

#include <ngtcp2/ngtcp2.h>
#include <uv.h>

namespace quic {

using bstring_view = std::basic_string_view<std::byte>;

class Endpoint;
class Server;
class Client;

struct alignas(size_t) ConnectionID : ngtcp2_cid {
    ConnectionID() = default;
    ConnectionID(const uint8_t* cid, size_t length);
    ConnectionID(const ConnectionID& c) = default;
    ConnectionID& operator=(const ConnectionID& c) = default;

    static constexpr size_t max_size() { return NGTCP2_MAX_CIDLEN; }
    static_assert(NGTCP2_MAX_CIDLEN <= std::numeric_limits<uint8_t>::max());

    bool operator==(const ConnectionID& other) const {
        return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
    }
    bool operator!=(const ConnectionID& other) const { return !(*this == other); }

    template <typename RNG>
    static ConnectionID random(RNG&& rng) {
        ConnectionID r;
        random_bytes(r.data, r.max_size(), rng);
        return r;
    }
};
std::ostream& operator<<(std::ostream& o, const ConnectionID& c);

}
namespace std {
template <> struct hash<quic::ConnectionID> {
    // We pick our own source_cid randomly, so it's a perfectly good hash already.
    size_t operator()(const quic::ConnectionID& c) const {
        static_assert(alignof(quic::ConnectionID) >= alignof(size_t) && offsetof(quic::ConnectionID, data) % sizeof(size_t) == 0);
        return *reinterpret_cast<const size_t*>(c.data);
    }
};
}
namespace quic {

/// Returns the current (monotonic) time
inline auto now() { return std::chrono::steady_clock::now(); }

/// Returns a monotonic nanosecond timestamp as ngtcp2 expects.
inline uint64_t get_timestamp() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
            now().time_since_epoch()).count();
}

// Stores an established connection between server/client.
class Connection {
private:
    struct connection_deleter { void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); } };
    struct uv_async_deleter {
        void operator()(uv_async_t* a) const {
            uv_close(reinterpret_cast<uv_handle_t*>(a), nullptr);
            delete a;
        }
    };

    // The endpoint that owns this connection
    Endpoint& endpoint;

    // Packet data storage for a packet we are currently sending
    std::basic_string<std::byte> send_buffer{NGTCP2_MAX_PKTLEN_IPV4, std::byte{0}};

    // Attempts to send the packet in `send_buffer`.  If sending blocks then we set up a write poll
    // on the socket to wait for it to become available.  Returns true if we sent, false if an error
    // occured (including, but not limited to, the case where we had to defer with the write poll).
    bool send();

    // Poll for writability; activated if we block while trying to send a packet.
    uv_poll_t wpoll;
    bool wpoll_active = false;

    // Internal base method called invoked during construction to set up common client/server
    // settings.  dest_cid and path must already be set.
    std::pair<ngtcp2_settings, ngtcp2_callbacks> init(Endpoint& ep);

    // Event trigger used to queue packet processing for this connection
    std::unique_ptr<uv_async_t, uv_async_deleter> io_trigger;

public:
    /// The destination connection id we use to send to the other end
    ConnectionID dest_cid;
    /// The underlying ngtcp2 connection object
    std::unique_ptr<ngtcp2_conn, connection_deleter> conn;
    /// The most recent Path we have to/from the remote
    Path path;
    /// True if we are draining (that is, we recently received a connection close from the other end
    /// and should discard everything that comes in on this connection).  Do not set this directly:
    /// instead call Endpoint::start_draining(conn).
    bool draining = false;

    /// The closing stanza; empty until we start closing the connection
    std::basic_string<std::byte> closing;

    /// Alternative connection id's by which we are known; these IDs will have keys in
    /// Endpoint.conn_alias that point to our primary connection ID.
    std::unordered_set<ConnectionID> aliases;

    /// Constructs and initializes a new connection received by a Server
    ///
    /// \param endpoint - the Server object on which the connection was initiated
    /// \param scid - the source (i.e. local) ConnectionID for this connection, typically random
    /// \param header - packet header that initiated the connection
    /// \param path - the network path to reach the remote
    Connection(Server& s, const ConnectionID& scid, ngtcp2_pkt_hd& header, const Path& path);

    /// Establishes a connection from the local Client to a remote Server
    Connection(Client& c, const Path& path);

    // Non-movable, non-copyable:
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    operator const ngtcp2_conn*() const { return conn.get(); }
    operator ngtcp2_conn*() { return conn.get(); }

    void io_callback();
    void on_read(bstring_view data);
};

}
