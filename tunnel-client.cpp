#include "connection.h"
#include "client.h"
#include "log.h"
#include "stream.h"
#include "tunnel.h"

#include <charconv>
#include <iterator>

#include <uvw.hpp>

using namespace std::literals;

// When we receive a new incoming connection we immediately initiate a new quic stream.  This quic
// stream in turn causes the other end to initiate a TCP connection on whatever port we specified in
// the connection; if the connection is established, it sends back a single byte 0x00
// (CONNECT_INIT); otherwise it shuts down the stream with an error code.
void on_new_connection(const uvw::ListenEvent&, uvw::TCPHandle& server) {
    quic::Debug("New connection!\n");
    auto client = server.loop().resource<uvw::TCPHandle>();
    server.accept(*client);

    auto conn = server.data<quic::Connection>();
    std::shared_ptr<quic::Stream> stream;
    try {
        quic::Debug("open stream");
        stream = conn->open_stream([client](quic::Stream& stream, quic::bstring_view bdata) {
            if (bdata.empty()) return;
            if (auto b0 = bdata[0]; b0 == tunnel::CONNECT_INIT) {
                // Set up callbacks, which replaces both of these initial callbacks
                client->read();
                tunnel::install_stream_forwarding(*client, stream);

                if (bdata.size() > 1) {
                    bdata.remove_prefix(1);
                    stream.data_callback(stream, std::move(bdata));
                }
                quic::Debug("starting client reading");
            } else {
                quic::Warn("Remote connection returned invalid initial byte (0x", oxenmq::to_hex(bdata.begin(), bdata.begin()+1), "); dropping connection");
                client->closeReset();
                stream.close(tunnel::ERROR_BAD_INIT);
            }
            stream.io_ready();
        }, [client](quic::Stream& stream, std::optional<uint64_t> error_code) mutable {
            if (error_code && *error_code == tunnel::ERROR_CONNECT)
                quic::Debug("Remote TCP connection failed, closing local connection");
            else
                quic::Warn("Stream connection closed ", error_code ? "with error " + std::to_string(*error_code) : "gracefully",
                        "; closing local TCP connection.");
            auto peer = client->peer();
            quic::Debug("Closing connection to ", peer.ip, ":", peer.port);
            if (error_code)
                client->closeReset();
            else
                client->close();
        });
        stream->io_ready();
    } catch (const std::exception& e) {
        quic::Debug("open stream failed");
        client->closeReset();
        return;
    }

    quic::Debug("setup stream");
    conn->io_ready();
}

int usage(std::string_view arg0, std::string_view msg) {
    std::cerr << msg << "\n\n" << "Usage: " << arg0 << " [DESTPORT [SERVERPORT [LISTENPORT]]]\n\nDefaults to ports 4444 4242 5555\n";
    return 1;
}

int main(int argc, char *argv[]) {
    auto loop = uvw::Loop::create();

    std::array<uint16_t, 3> ports{{4444, 4242, 5555}};
    for (size_t i = 0; i < ports.size(); i++) {
        if (argc < 2+i) break;
        if (!tunnel::parse_int(argv[1+i], ports[i]))
            return usage(argv[0], "Invalid port "s + argv[1+i]);
    }
    auto& [dest_port, server_port, listen_port] = ports;
    std::cout << "Connecting to quic server at localhost:" << server_port << " to reach tunneled port " << dest_port << ", listening on localhost:" << listen_port << "\n";

    signal(SIGPIPE, SIG_IGN);

    quic::Debug("Initializing client");
    auto tunnel_client = std::make_shared<quic::Client>(
        quic::Address{{127,0,0,1}, server_port}, // server addr
        loop,
        dest_port // tunnel destination port
        );
    tunnel_client->default_stream_buffer_size = 0; // We steal uvw's provided buffers
    quic::Debug("Initialized client");

    // Start listening for TCP connections:
    auto server = loop->resource<uvw::TCPHandle>();
    server->data(tunnel_client->get_connection());
    server->on<uvw::ListenEvent>(on_new_connection);

    server->bind("127.0.0.1", listen_port);
    server->listen();

    loop->run();
}
