#include "connection.h"
#include "server.h"
#include "log.h"

#include "tunnel.h"

#include <uvw.hpp>

void listen(uvw::Loop &loop) {
    auto tcp = loop.resource<uvw::TCPHandle>();

    tcp->on<uvw::ListenEvent>([](const uvw::ListenEvent &, uvw::TCPHandle &srv) {
        auto client = srv.loop().resource<uvw::TCPHandle>();

        client->on<uvw::CloseEvent>([ptr = srv.shared_from_this()](const uvw::CloseEvent &, uvw::TCPHandle &) { ptr->close(); });
        client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle &client) { client.close(); });

        srv.accept(*client);
        client->read();
    });

    tcp->bind("127.0.0.1", 4242);
    tcp->listen();
}

int main() {
    auto loop = uvw::Loop::create();

    quic::Address listen{{127,0,0,1}, 4242};

    // The local address we connect to for incoming connections.  (localhost for this demo, should
    // be the localhost.loki address for lokinet).
    std::string localhost = "127.0.0.1";
    // Accept connections on any of this ports; if empty accept connection to any port.
    std::unordered_set allowed_ports{{8880, 8888, 8889, 8890, 8898, 8899}};

    quic::Debug("Initializing server");
    quic::Server s{listen, loop,
        [loop, localhost, allowed_ports](quic::Server& server, quic::Stream& stream, uint16_t port) {
            quic::Debug("New incoming quic stream ", stream.id(), " to reach ", localhost, ":", port);
            if (port == 0 || !(allowed_ports.empty() || allowed_ports.count(port))) {
                quic::Warn("quic stream denied by configuration: ", port, " is not a permitted local port");
                return false;
            }
            // Try to open a TCP connection to the configured localhost port
            auto tcp = loop->resource<uvw::TCPHandle>();
            tunnel::install_stream_forwarding(*tcp, stream);

            tcp->once<uvw::ConnectEvent>([](const uvw::ConnectEvent &, uvw::TCPHandle &tcp) {
                auto peer = tcp.peer();
                auto stream = tcp.data<quic::Stream>();
                if (!stream) {
                    quic::Warn("Connected to ", peer.ip, ":", peer.port, " but quic stream has gone away; resetting local connection");
                    tcp.closeReset();
                    return;
                }
                quic::Debug("Connected to ", peer.ip, ":", peer.port, " for quic ", stream->id());
            });
            return true;
        }
    };
    quic::Debug("Initialized server");

    loop->run();

    return 0;
}
