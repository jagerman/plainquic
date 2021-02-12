#include "connection.h"
#include "client.h"
#include "log.h"
#include "stream.h"

#include <iterator>

#include <uvw.hpp>


void on_new_connection(const uvw::ListenEvent&, uvw::TCPHandle& server) {
    auto client = server.loop().resource<uvw::TCPHandle>();

    std::shared_ptr<quic::Stream> stream;
    try {
        stream = server.data<quic::Connection>()->open_stream(
                [client](auto& stream, quic::bstring_view bdata) {
                    std::string_view data{reinterpret_cast<const char*>(bdata.data()), bdata.size()};
                    quic::Debug("lokinet -> ", client->peer().ip, ":", client->peer().port, " ", quic::buffer_printer{data});

                    if (data.empty())
                        return;

                    // Try first to write immediately from the existing buffer to avoid needing an
                    // allocation and copy:
                    auto written = client->tryWrite(const_cast<char*>(data.data()), data.size());
                    if (written < data.size())
                        data.remove_prefix(written);

                    auto wdata = std::make_unique<char[]>(data.size());
                    std::copy(data.begin(), data.end(), wdata.get());
                    client->write(std::move(wdata), data.size());
                },
                [client](quic::Stream& s) {
                    quic::Debug("lokinet side closed stream, closing ", client->peer().ip, ":", client->peer().port);
                    s.close(true);
                });
    } catch (const std::exception& e) {
        server.accept(*client);
        client->closeReset();
        return;
    }

    client->data(stream);
    client->on<uvw::CloseEvent>([](auto&, uvw::TCPHandle& c) { quic::Debug("CloseEvent"); c.data<quic::Stream>()->close(); });
    client->on<uvw::EndEvent>([](auto&, uvw::TCPHandle& c) { quic::Debug("EndEvent"); c.close(); }); // FIXME - will this have called CloseEvent already?
    client->on<uvw::DataEvent>([](const uvw::DataEvent& event, uvw::TCPHandle& client) {
        auto stream = client.data<quic::Stream>();
        std::string_view data{event.data.get(), event.length};
        quic::Debug(client.peer().ip, ":", client.peer().port, " -> lokinet ", quic::buffer_printer{data});
        if (auto wrote = stream->append_any(data); wrote < data.size()) {
            // This gets complicated: we've received some data to forward but the stream's
            // internal buffer is full of unacknowledged data.  We have to basically pause the
            // local socket until the situation improves, and keep a sort of "overflow" buffer
            // here to be reinserted once the stream space frees up.
            client.stop();
            data.remove_prefix(wrote);
            stream->when_available(data.size(), [client = client.shared_from_this(), overflow = std::string{data}](quic::Stream& s) {
                [[maybe_unused]] bool appended = s.append(overflow);
                assert(appended);
                client->read();
            });
        }
    });

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
