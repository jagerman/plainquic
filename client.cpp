
#include "client.h"
#include "log.h"

#include <oxenmq/variant.h>

namespace quic {

Client::Client(Address remote, std::shared_ptr<uvw::Loop> loop_, uint16_t tunnel_port, std::optional<Address> local_)
        : Endpoint{std::move(local_), std::move(loop_)} {

    // Our UDP socket is now set up, so now we initiate contact with the remote QUIC
    Path path{local, remote};
    Debug("Connecting to ", remote);

    // TODO: need timers for:
    //
    // - timeout (to disconnect if idle for too longer)
    //
    // - probably don't need for lokinet tunnel: change local addr -- attempts to re-bind the local socket
    //
    // - key_update_timer
    //
    // - delay_stream_timer


    auto connptr = std::make_shared<Connection>(*this, ConnectionID::random(rng), path);
    auto& conn = *connptr;
    conns.emplace(conn.base_cid, connptr);

/*    Debug("set crypto ctx");

    null_crypto.client_initial(conn);

    auto x = ngtcp2_conn_get_max_data_left(conn);
    Debug("mdl = ", x);
    */

    conn.io_ready();

    /*
    Debug("Opening bidi stream");
    int64_t stream_id;
    if (auto rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
            rv != 0) {
        Debug("Opening bidi stream failed: ", ngtcp2_strerror(rv));
        assert(rv == NGTCP2_ERR_STREAM_ID_BLOCKED);
    }
    else { Debug("Opening bidi stream good"); }
    */
}

std::shared_ptr<Connection> Client::get_connection() {
    // A client only has one outgoing connection, so everything in conns should either be a
    // shared_ptr or weak_ptr to that same outgoing connection so we can just use the first one.
    auto it = conns.begin();
    if (it == conns.end())
        return nullptr;
    if (auto* wptr = std::get_if<alias_conn_ptr>(&it->second))
        return wptr->lock();
    return std::get<primary_conn_ptr>(it->second);
}

void Client::handle_packet(const Packet& p) {
    Debug("Handling incoming client packet: ", buffer_printer{p.data});
    auto maybe_dcid = handle_packet_init(p);
    if (!maybe_dcid) return;
    auto& dcid = *maybe_dcid;

    Debug("Incoming connection id ", dcid);
    auto [connptr, alias] = get_conn(dcid);
    if (!connptr) {
        Debug("CID is ", alias ? "expired alias" : "unknown/expired", "; dropping");
        return;
    }
    auto& conn = *connptr;
    if (alias)
        Debug("CID is alias for primary CID ", conn.base_cid);
    else
        Debug("CID is primary CID");

    handle_conn_packet(conn, p);
}

}
