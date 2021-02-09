#pragma once

#include "address.h"
#include "random.h"
#include "stream.h"
#include "io_result.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_set>
#include <map>

#include <ngtcp2/ngtcp2.h>
#include <uv.h>

namespace quic {

// We send and verify this in the initial connection and handshake; this is designed to allow future
// changes (by either breaking or handling backwards compat).
constexpr const std::array<uint8_t, 8> handshake_magic_bytes{'l','o','k','i','n','e','t',0x01};
constexpr std::basic_string_view<uint8_t> handshake_magic{handshake_magic_bytes.data(), handshake_magic_bytes.size()};

using bstring_view = std::basic_string_view<std::byte>;

class Endpoint;
class Server;
class Client;

struct alignas(size_t) ConnectionID : ngtcp2_cid {
    ConnectionID() = default;
    ConnectionID(const uint8_t* cid, size_t length);
    ConnectionID(const ConnectionID& c) = default;
    ConnectionID(ngtcp2_cid c) : ConnectionID(c.data, c.datalen) {}
    ConnectionID& operator=(const ConnectionID& c) = default;

    static constexpr size_t max_size() { return NGTCP2_MAX_CIDLEN; }
    static_assert(NGTCP2_MAX_CIDLEN <= std::numeric_limits<uint8_t>::max());

    bool operator==(const ConnectionID& other) const {
        return datalen == other.datalen && std::memcmp(data, other.data, datalen) == 0;
    }
    bool operator!=(const ConnectionID& other) const { return !(*this == other); }

    template <typename RNG>
    static ConnectionID random(RNG&& rng, size_t size = ConnectionID::max_size()) {
        ConnectionID r;
        r.datalen = r.max_size();
        random_bytes(r.data, r.datalen, rng);
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

/// Returns the current (monotonic) time as a time_point
inline auto get_time() { return std::chrono::steady_clock::now(); }

/// Converts a time_point as returned by get_time to a nanosecond timestamp (as ngtcp2 expects).
inline uint64_t get_timestamp(const std::chrono::steady_clock::time_point &t = get_time()) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
}

// Stores an established connection between server/client.
class Connection : public std::enable_shared_from_this<Connection> {
private:
    struct connection_deleter { void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); } };
    struct uv_async_deleter {
        void operator()(uv_async_t* a) const {
            // We can't actually do the delete right away because uv_close is asynchronous: tell it
            // to clean up and then do the actual delete in the callback it invokes when it's done.
            uv_close(reinterpret_cast<uv_handle_t*>(a), [](uv_handle_t* delete_me) {
                delete reinterpret_cast<uv_async_t*>(delete_me); });
        }
    };

    // Packet data storage for a packet we are currently sending
    std::array<std::byte, NGTCP2_MAX_PKTLEN_IPV4> send_buffer{};
    size_t send_buffer_size = 0;
    ngtcp2_pkt_info send_pkt_info{};

    // Attempts to send the packet in `send_buffer`.  If sending blocks then we set up a write poll
    // on the socket to wait for it to become available, and return an io_result with `.blocked()`
    // set to true.  On other I/O errors we return the errno, and on successful sending we return a
    // "true" (i.e. no error code) io_result.
    io_result send();

    // Poll for writability; activated if we block while trying to send a packet.
    uv_poll_t wpoll;
    bool wpoll_active = false;

    // Internal base method called invoked during construction to set up common client/server
    // settings.  dest_cid and path must already be set.
    std::tuple<ngtcp2_settings, ngtcp2_transport_params, ngtcp2_callbacks> init(Endpoint& ep);

    // Event trigger used to queue packet processing for this connection
    std::unique_ptr<uv_async_t, uv_async_deleter> io_trigger;

public:
    // The endpoint that owns this connection
    Endpoint& endpoint;

    /// The primary connection id of this Connection.  This is the key of endpoint.conns that stores
    /// the actual shared_ptr (everything else in `conns` is a weak_ptr alias).
    const ConnectionID base_cid;

    /// The destination connection id we use to send to the other end; the remote end sets this as
    /// the source cid in the header.
    ConnectionID dest_cid;

    /// The underlying ngtcp2 connection object
    std::unique_ptr<ngtcp2_conn, connection_deleter> conn;

    /// The most recent Path we have to/from the remote
    Path path;

    /// True if we are draining (that is, we recently received a connection close from the other end
    /// and should discard everything that comes in on this connection).  Do not set this directly:
    /// instead call Endpoint::start_draining(conn).
    bool draining = false;

    /// True when we are closing; conn_buffer will contain the closing stanza.
    bool closing = false;

    /// Buffer where we store non-stream connection data, e.g. for initial transport params during
    /// connection and the closing stanza when disconnecting.
    std::basic_string<std::byte> conn_buffer;

    // Stores callbacks of active streams, indexed by our local source connection ID that we assign
    // when the connection is initiated.
    std::map<int64_t, Stream> streams;

    /// Constructs and initializes a new connection received by a Server
    ///
    /// \param s - the Server object on which the connection was initiated
    /// \param base_cid - the local "primary" ConnectionID we use for this connection, typically random
    /// \param header - packet header that initiated the connection
    /// \param path - the network path to reach the remote
    Connection(Server& s, const ConnectionID& base_cid, ngtcp2_pkt_hd& header, const Path& path);

    /// Establishes a connection from the local Client to a remote Server
    /// \param c - the Client object from which the connection is being made
    /// \param base_cid - the client's source (i.e. local) connection ID, typically random
    /// \param path - the network path to reach the remote
    Connection(Client& c, const ConnectionID& scid, const Path& path);

    // Non-movable, non-copyable:
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    operator const ngtcp2_conn*() const { return conn.get(); }
    operator ngtcp2_conn*() { return conn.get(); }

    // If this connection's endpoint is a server, returns a pointer to it.  Otherwise returns
    // nullptr.
    Server* server();

    // If this connection's endpoint is a client, returns a pointer to it.  Otherwise returs
    // nullptr.
    Client* client();

    // Called to signal libuv that this connection has stuff to do
    void io_ready();
    // Called (via libuv) when it wants us to do our stuff. Call io_ready() to schedule this.
    void io_callback();

    void on_read(bstring_view data);
    int setup_server_crypto_initial();

    // Flush any streams with pending data. Note that, depending on available ngtcp2 state, we may
    // not fully flush all streams.
    void flush_streams();

    // Asks the endpoint for a new connection ID alias to use for this connection.  cidlen can be
    // used to specify the size of the cid (default is full size).
    ConnectionID make_alias_id(size_t cidlen = ConnectionID::max_size());

    int init_client();
    bool init_tx_key();

    int recv_initial_crypto(std::basic_string_view<uint8_t> data);
    int recv_transport_params(std::basic_string_view<uint8_t> data);
    int send_magic(ngtcp2_crypto_level level);
    int send_transport_params(ngtcp2_crypto_level level);
    void complete_handshake();
};

}
