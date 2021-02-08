#pragma once

#include "endpoint.h"

namespace quic {

class Server : public Endpoint {

public:
    Server(Address listen, uv_loop_t* loop);

    int setup_null_crypto(ngtcp2_conn* conn);

private:
    // Handles an incoming packet by figuring out and handling the connection id; if necessary we
    // send back a version negotiation or a connection close frame, or drop the packet (if in the
    // draining state).  If we get through all of the above then it's a packet to read, in which
    // case we pass it on to read_packet().
    void handle_packet(const Packet& p) override;

    // Creates a new connection from an incoming packet.  Returns a nullptr if the connection can't
    // be created.
    std::shared_ptr<Connection> accept_connection(const Packet& p);
};

}
