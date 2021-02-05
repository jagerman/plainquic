#include "server.h"
#include "log.h"

#include <oxenmq/hex.h>

#include <stdexcept>
#include <tuple>

namespace quic {

Server::Server(Address listen, uv_loop_t* loop) : Endpoint{std::move(listen), loop} {
}

void Server::handle_packet(const Packet& p) {
    version_info vi;
    Debug("Handling incoming server packet: ", make_printable(p.data));
    auto rv = ngtcp2_pkt_decode_version_cid(&vi.version, &vi.dcid, &vi.dcid_len, &vi.scid, &vi.scid_len,
            u8data(p.data), p.data.size(), NGTCP2_MAX_CIDLEN);
    if (rv == 1) // 1 means Version Negotiation should be sent
        return send_version_negotiation(vi, p.path.remote);
    else if (rv != 0) {
        Warn("QUIC packet header decode failed: ", ngtcp2_strerror(rv));
        return;
    }

    if (vi.dcid_len > ConnectionID::max_size()) {
        Warn("Internal error: destination ID is longer than should be allowed");
        return;
    }

    // See if we have an existing connection already established for it
    ConnectionID dcid{vi.dcid, vi.dcid_len};
    Debug("Incoming connection id ", dcid);
    auto conn_it = conns.find(dcid);
    if (conn_it == conns.end()) {
        // Look for a cid alias
        if (auto alias_it = conn_alias.find(dcid); alias_it != conn_alias.end()) {
            Debug("Found cid alias: ", dcid, " -> ", alias_it->second);
            conn_it = conns.find(alias_it->second);
        } else {
            // FIXME: what if this is a client?  Drop it?
            conn_it = accept_connection(p);
        }

        if (conn_it == conns.end()) {
            Warn(); // FIXME
            return;
        }

    }
    // FIXME: there are also connection ID aliases we need to worry about

    if (conn_it == conns.end()) {
        Warn("invalid or expired connection, ignoring");
        return;
    }

    auto& [cid, conn] = *conn_it;

    if (ngtcp2_conn_is_in_closing_period(conn)) {
        Debug("Connection is in closing period, dropping");
        close_connection(std::move(conn_it));
        return;
    }
    if (conn.draining) {
        Debug("Connection is draining, dropping");
        // "draining" state means we received a connection close and we're keeping the
        // connection alive just to catch (and discard) straggling packets that arrive
        // out of order w.r.t to connection close.
        return;
    }

    auto result = read_packet(p, conn_it);

    if (!result) {
        Debug("Read packet failed! ", ngtcp2_strerror(result.error_code));
    }
    // FIXME - reset idle timer?
    Debug("Done with incoming packet");
}

auto Server::accept_connection(const Packet& p) -> conns_iterator {
    Debug("Accepting new connection");
    // This is a new incoming connection
    ngtcp2_pkt_hd hd;
    auto rv = ngtcp2_accept(&hd, u8data(p.data), p.data.size());

    if (rv == -1) { // Invalid packet
        Warn("Invalid packet received, length=", p.data.size());
#ifndef NDEBUG
        Debug("packet body:");
        for (size_t i = 0; i < p.data.size(); i += 50)
            Debug("  ", oxenmq::to_hex(p.data.substr(i, 50)));
#endif
        return conns.end();
    }

    if (rv == 1) { // Invalid/unexpected version, send a version negotiation
        Debug("Invalid/unsupported version; sending version negotiation");
        send_version_negotiation(
                version_info{hd.version, hd.dcid.data, hd.dcid.datalen, hd.scid.data, hd.scid.datalen},
                p.path.remote);
        return conns.end();
    }

    /*
    ngtcp2_cid ocid;
    ngtcp2_cid *pocid = nullptr;
    */
    if (hd.type == NGTCP2_PKT_0RTT) {
        Warn("Received 0-RTT packet, which shouldn't happen in our implementation; dropping");
        return conns.end();
    } else if (hd.type == NGTCP2_PKT_INITIAL && hd.token.len) {
        // This is a normal QUIC thing, but we don't do it:
        Warn("Unexpected token in initial packet");
    }

    // create and store Connection
    ConnectionID local_cid;
    do { local_cid = ConnectionID::random(rng); } while (conns.count(local_cid));

    Debug("Created local cid ", local_cid, " for incoming connection");

    conns_iterator it = conns.end();
    try {
        auto [insit, ins] = conns.emplace(std::piecewise_construct,
                std::forward_as_tuple(local_cid),
                std::forward_as_tuple(*this, local_cid, hd, p.path));
        if (!ins)
            Warn("Internal error: duplicate connection id?");
        else
            it = insit;
    } catch (const std::exception& e) {
        Warn("Failed to create Connection: ", e.what());
    }

    //ngtcp2_conn_set_tls_native_handle(conn_, tls_session_.get_native_handle());

    return it;
}


}
