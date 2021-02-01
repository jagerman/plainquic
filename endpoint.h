#pragma once

#include "address.h"
#include "connection.h"
#include "packet.h"

#include <chrono>
#include <queue>
#include <random>
#include <unordered_map>
#include <vector>

#include <uv.h>

#if defined(__linux__) && !defined(NO_RECVMMSG)
#  define LOKINET_HAVE_RECVMMSG
#endif

namespace quic {

using namespace std::literals;

inline constexpr auto IDLE_TIMEOUT = 60s;

// Return result from a read or write operation that wraps an error code value. It is implicitly
// convertible to bool to test for "is not an error" (which is the inverse of casting a plain
// integer error code value to bool).
struct io_result {
    // An error code; depending on the context this could be an errno value or an ngtcp2 error
    // value.  Will be 0 for a successful operation.
    int error_code{0};
    // Returns true if this represent a successful result, i.e. an error_code of 0.
    operator bool() const { return error_code == 0; }
};

// Stores an established stream (a single connection has multiple streams).
struct Stream {
    // FIXME: stream id?
    std::function<void(std::string_view data)> callback;
};

class Endpoint {
protected:
    // Address we are listening on
    Address local;
    // The current outgoing IP ecn value for the socket
    uint8_t ecn_curr = 0;
    // The ecn we want for the next packet (we defer actually making the syscall until we actually
    // try to send such a packet and it differs from ecn_curr).
    uint8_t ecn_next = 0;

    //uv_udp_t sock;
    uv_poll_t poll;
    uv_timer_t expiry_timer;
    uv_loop_t* loop;

    // How many messages (at most) we recv per callback:
    static constexpr size_t N_msgs = 8;
#ifdef LOKINET_HAVE_RECVMMSG
    static constexpr size_t N_mmsg = N_msgs;
    std::array<mmsghdr, N_mmsg> msgs;
#else
    static constexpr size_t N_mmsg = 1;
    std::array<msghdr, N_mmsg> msgs;
#endif

    std::array<iovec, N_mmsg> msgs_iov;
    std::array<sockaddr_any, N_mmsg> msgs_addr;
    std::array<std::array<uint8_t, CMSG_SPACE(1)>, N_mmsg> msgs_cmsg;
    std::vector<std::byte> buf;
    // Max theoretical size of a UDP packet is 2^16-1 minus IP/UDP header overhead
    static constexpr size_t max_buf_size = 64*1024;
    // Max size of a UDP packet that we'll send
    static constexpr size_t max_pkt_size_v4 = NGTCP2_MAX_PKTLEN_IPV4;
    static constexpr size_t max_pkt_size_v6 = NGTCP2_MAX_PKTLEN_IPV6;

    std::mt19937_64 rng = seeded<std::mt19937_64>();

    // Connection.  When a client establishes a new connection it chooses its own source connection
    // ID and a destination connection ID and sends them to the server.
    //
    // The destination connection ID should be entirely random and can be up to 160 bits, but the
    // source connection ID does not have to be (i.e. it can encode some information, if desired).
    //
    // The server is going to include in the response:
    // - destination connection ID equal to the client's source connection ID
    // - a new random source connection ID.  (We don't use the client's destination ID but generate
    // our own).  Like the clients source ID, this can contain embedded info.
    //
    // The client stores this, and so we end up with client-scid == server-dcid, and client-dcid ==
    // server-scid, where each side chose its own source connection ID.
    //
    // Ultimately, we store here our own {source connection ID -> Connection} pairs (or
    // equivalently, on incoming packets, the key will be the packet's dest conn ID).
    std::unordered_map<ConnectionID, Connection> conns;

    using conns_iterator = decltype(conns)::iterator;

    // Connection aliases; the key is an ephemeral connection ID that points to the underlying core
    // ConnectionID where we store the actual Connection.  We provide the client with these aliases
    // to talk to us.  Every alias here should also be in the Connection's `aliases` set.
    std::unordered_map<ConnectionID, ConnectionID> conn_alias;

    // Connections that are draining (i.e. we are dropping, but need to keep around for a while
    // to catch and drop lagged packets).  The time point is the scheduled removal time.
    std::queue<std::pair<ConnectionID, std::chrono::steady_clock::time_point>> draining;

    //
    // the server is establishing
    // can encode information
    // Stores callbacks of active streams, indexed by our local source connection ID that we assign
    // when the connection is initiated.
    std::unordered_map<std::string, Stream> streams;

    friend class Connection;

    // Wires up an endpoint connection.
    //
    // `bind` - address we should bind to.  Required for a server, optional for a client.  If
    // omitted, no explicit bind is performed (which means the socket will be implicitly bound to
    // some OS-determined random high bind port).
    // `loop` - the uv_loop pointer managing polling of this endpoint
    Endpoint(std::optional<Address> bind, uv_loop_t* loop);

    int socket_fd() const {
        int ret;
        uv_fileno(reinterpret_cast<const uv_handle_t*>(&poll), &ret);
        return ret;
    }

    void poll_callback(int status, int events);

    // Version & connection id info that we can potentially extract when decoding a packet
    struct version_info {
        uint32_t version;
        const uint8_t *dcid;
        size_t dcid_len;
        const uint8_t *scid;
        size_t scid_len;
    };

    // Called to handle an incoming packet
    virtual void handle_packet(const Packet& p) = 0;

    // Reads a packet and handles various error conditions.  Returns an io_result.  Note that it is
    // possible for the conn_it to be erased from `conns` if the error code is anything other than
    // success (0) or NGTCP2_ERR_RETRY.
    io_result read_packet(const Packet& p, conns_iterator conn_it);

    // Sets up the ECN IP field (IP_TOS for IPv4) for the next outgoing packet sent via
    // send_packet().  This does the actual syscall (if ECN is different than currently set), and is
    // typically called implicitly via send_packet().
    void update_ecn();

    // Sends a packet to `to` containing `data`. Returns a non-error io_result on success,
    // an io_result with .error_code set to the errno of the failure on failure.
    io_result send_packet(const Address& to, bstring_view data);

    // Wrapper around the above that takes a regular std::string_view (i.e. of chars) and recasts
    // it to an string_view of std::bytes.
    io_result send_packet(const Address& to, std::string_view data) {
        return send_packet(to, bstring_view{reinterpret_cast<const std::byte*>(data.data()), data.size()});
    }

    // Another wrapper taking a vector
    io_result send_packet(const Address& to, const std::vector<std::byte>& data) {
        return send_packet(to, bstring_view{data.data(), data.size()});
    }

    void send_version_negotiation(const version_info& vi, const Address& source);

    // Called to start closing (or continue closing) a connection by sending a connection close
    // response to any incoming packets.
    //
    // Takes the iterator to the connection pair from `conns` and optional error parameters: if
    // `application` is false (the default) then we do a hard connection close because of transport
    // error, if true we do a graceful application close.  For application closes the code is
    // application-defined; for hard closes the code should be one of the NGTCP2_*_ERROR values.
    void close_connection(conns_iterator cit, uint64_t code = NGTCP2_NO_ERROR, bool application = false);

    /// Puts a connection into draining mode (i.e. after getting a connection close).  This will
    /// keep the connection registered for the recommended 3*Probe Timeout, during which we drop
    /// packets that use the connection id and after which we will forget about it.
    void start_draining(const conns_iterator& cit);

    void check_timeouts();

    /// Deletes a connection from `conns`, including all connection id aliases to the connection
    conns_iterator delete_conn(conns_iterator cit);

    virtual ~Endpoint() = default;
};

}
