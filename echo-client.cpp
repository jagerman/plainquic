#include "connection.h"
#include "client.h"
#include "log.h"
#include "stream.h"
#include "tunnel.h"

#include <iterator>

#include <uvw.hpp>

void on_new_connection(const uvw::ListenEvent&, uvw::TCPHandle& server) {
    auto client = server.loop().resource<uvw::TCPHandle>();

    std::shared_ptr<quic::Stream> stream;
    try {
        stream = server.data<quic::Connection>()->open_stream(tunnel::on_incoming_data, tunnel::on_remote_close);
    } catch (const std::exception& e) {
        server.accept(*client);
        client->closeReset();
        return;
    }

    tunnel::install_stream_forwarding(*client, *stream);
    server.accept(*client);
    client->read();
}

int main() {
    auto loop = uvw::Loop::create();

    quic::Debug("Initializing client");
    auto tunnel_client = std::make_shared<quic::Client>(
        quic::Address{{127,0,0,1}, 4242}, // server addr
        loop,
        4444 // tunnel port
        );
    quic::Debug("Initialized client");

    // Start listening for TCP connections:
    auto server = loop->resource<uvw::TCPHandle>();
    server->data(tunnel_client->get_connection());
    server->on<uvw::ListenEvent>(on_new_connection);

    server->bind("127.0.0.1", 5555);
    server->listen();

    loop->run();
}
