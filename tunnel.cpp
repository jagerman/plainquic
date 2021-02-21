#include "tunnel.h"
#include "log.h"
#include "stream.h"
#include "uvw/tcp.h"

namespace tunnel {

// Takes data from the tcp connection and pushes it down the quic tunnel
void on_outgoing_data(uvw::DataEvent& event, uvw::TCPHandle& client) {
    auto stream = client.data<quic::Stream>();
    assert(stream);
    std::string_view data{event.data.get(), event.length};
    auto peer = client.peer();
    quic::Debug(peer.ip, ":", peer.port, " → lokinet ", quic::buffer_printer{data});
    // Steal the buffer from the DataEvent's unique_ptr<char[]>:
    stream->append_buffer(reinterpret_cast<const std::byte*>(event.data.release()), event.length);
    if (stream->used() >= PAUSE_SIZE) {
        quic::Debug("quic tunnel is congested (have ", stream->used(), " bytes in flight); pausing local tcp connection reads");
        client.stop();
        stream->when_available([](quic::Stream& s) {
            auto client = s.data<uvw::TCPHandle>();
            if (s.used() < PAUSE_SIZE) {
                quic::Debug("quic tunnel is no longer congested; resuming tcp connection reading");
                client->read();
                return true;
            }
            return false;
        });
    } else {
        quic::Debug("Queued ", event.length, " bytes");
    }
}

// Received data from the quic tunnel and sends it to the TCP connection
void on_incoming_data(quic::Stream& stream, quic::bstring_view bdata) {
    auto tcp = stream.data<uvw::TCPHandle>();
    assert(tcp);
    std::string_view data{reinterpret_cast<const char*>(bdata.data()), bdata.size()};
    auto peer = tcp->peer();
    quic::Debug(peer.ip, ":", peer.port, " ← lokinet ", quic::buffer_printer{data});

    if (data.empty())
        return;

    // Try first to write immediately from the existing buffer to avoid needing an
    // allocation and copy:
    auto written = tcp->tryWrite(const_cast<char*>(data.data()), data.size());
    if (written < data.size()) {
        data.remove_prefix(written);

        auto wdata = std::make_unique<char[]>(data.size());
        std::copy(data.begin(), data.end(), wdata.get());
        tcp->write(std::move(wdata), data.size());
    }
}

void install_stream_forwarding(uvw::TCPHandle& tcp, quic::Stream& stream) {
    tcp.data(stream.shared_from_this());
    stream.weak_data(tcp.weak_from_this());

    tcp.on<uvw::CloseEvent>([](auto&, uvw::TCPHandle& c) {
        // This fires sometime after we call `close()` to signal that the close is done.
        quic::Error("Connection with ", c.peer().ip, ":", c.peer().port, " closed directly, closing quic stream");
        c.data<quic::Stream>()->close();
    });
    tcp.on<uvw::EndEvent>([](auto&, uvw::TCPHandle& c) {
        // This fires on eof, most likely because the other side of the TCP connection closed it.
        quic::Error("EOF on connection with ", c.peer().ip, ":", c.peer().port, ", closing quic stream");
        c.data<quic::Stream>()->close();
    });
    tcp.on<uvw::ErrorEvent>([](const uvw::ErrorEvent &e, uvw::TCPHandle &tcp) {
        quic::Error("ErrorEvent[", e.name(), ": ", e.what(), "] on connection with ", tcp.peer().ip, ":", tcp.peer().port, ", shutting down quic stream");
        // Failed to open connection, so close the quic stream
        auto stream = tcp.data<quic::Stream>();
        if (stream)
            stream->close(ERROR_TCP);
        tcp.close();
    });
    tcp.on<uvw::DataEvent>(tunnel::on_outgoing_data);
    stream.data_callback = on_incoming_data;
}

}
