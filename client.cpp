
#include "client.h"
#include "log.h"

namespace quic {

Client::Client(Address remote, uv_loop_t* loop, std::optional<Address> local)
        : Endpoint{std::move(local), loop} {
    // Our UDP socket is now set up, so now we initiate contact with the remote QUIC
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


    conns_iterator it = conns.end();
    try {
        auto* s = dynamic_cast<Server*>(this);
        assert(s);
        auto [insit, ins] = conns.emplace(std::piecewise_construct,
                std::forward_as_tuple(local_cid),
                std::forward_as_tuple(*s, local_cid, hd, p.path));
        if (!ins)
            Warn("Internal error: duplicate connection id?");
        else
            it = insit;
    } catch (const std::exception& e) {
        Warn("Failed to create Connection: ", e.what());
    }


}

void Client::handle_packet(const Packet& p) {
    version_info vi;
    auto rv = ngtcp2_pkt_decode_version_cid(&vi.version, &vi.dcid, &vi.dcid_len, &vi.scid, &vi.scid_len,
            reinterpret_cast<const uint8_t*>(p.data.data()), p.data.size(), NGTCP2_MAX_CIDLEN);
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

}
