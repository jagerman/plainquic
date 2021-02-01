#pragma once

#include "endpoint.h"

#include <optional>

namespace quic {

class Client : public Endpoint {
public:
    // Constructs a client that establishes an outgoing connection to `remote`.  `local` can be used
    // to optionally bind to a local IP and/or port for the connection.
    Client(Address remote, uv_loop_t* loop, std::optional<Address> local = std::nullopt);

private:
    void handle_packet(const Packet& p) override;
};

}
