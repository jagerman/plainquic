#include "tunnel.h"
#include "uvw/tcp.h"

namespace tunnel {

void on_outgoing_data(const uvw::DataEvent& event, uvw::TCPHandle& client) {
    auto stream = client.data<quic::Stream>();
    assert(stream);
    std::string_view data{event.data.get(), event.length};
    auto peer = client.peer();
    quic::Debug(peer.ip, ":", peer.port, " → lokinet ", quic::buffer_printer{data});
    if (auto wrote = stream->append_any(data); wrote < data.size()) {
        // This gets complicated: we've received some data to forward but the stream's
        // internal buffer is full of unacknowledged data.  We have to basically pause the
        // local socket until the situation improves, and keep a sort of "overflow" buffer
        // here to be reinserted once the stream space frees up.
        quic::Debug("quic tunnel is congested (wrote ", wrote, " of ", data.size(), " bytes; pausing local tcp connection reads");
        client.stop();
        data.remove_prefix(wrote);
        stream->when_available(data.size(), [client = client.shared_from_this(), overflow = std::string{data}](quic::Stream& s) {
            quic::Debug("quic tunnel is no longer congested; resuming tcp connection reading");
            [[maybe_unused]] bool appended = s.append(overflow);
            assert(appended);
            client->read();
        });
    } else {
        quic::Debug("Sent ", wrote, " bytes");
    }
}
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
    if (written < data.size())
        data.remove_prefix(written);

    auto wdata = std::make_unique<char[]>(data.size());
    std::copy(data.begin(), data.end(), wdata.get());
    tcp->write(std::move(wdata), data.size());
}


void on_remote_close(quic::Stream& s, std::optional<uint64_t> code) {
    auto tcp = s.data<uvw::TCPHandle>();
    assert(tcp); // FIXME - maybe the TCPHandle could have gone away first?
    quic::Debug("lokinet side closed stream (", tunnel_error_str(code.value_or(0)), "); closing ",
            tcp->peer().ip, ":", tcp->peer().port);
    s.close(0, true);
}


void install_stream_forwarding(uvw::TCPHandle& tcp, quic::Stream& stream) {
    tcp.data(stream.shared_from_this());
    stream.weak_data(tcp.weak_from_this());

    tcp.on<uvw::CloseEvent>([](auto&, uvw::TCPHandle& c) {
        // This fires sometime after we call `close()` to signal that the close is done.
        quic::Debug("Connection with ", c.peer().ip, ":", c.peer().port, " closed directly, shutting down quic stream");
        c.data<quic::Stream>()->close(code(tunnel::tunnel_error::TCP_CLOSED));
    });
    tcp.on<uvw::EndEvent>([](auto&, uvw::TCPHandle& c) {
        // This fires on eof, most likely because the other side of the TCP connection closed it.
        quic::Debug("EOF on connection with ", c.peer().ip, ":", c.peer().port, ", shutting down quic stream");
        c.data<quic::Stream>()->close(code(tunnel::tunnel_error::TCP_CLOSED));
    });
    tcp.on<uvw::ErrorEvent>([](const uvw::ErrorEvent &, uvw::TCPHandle &tcp) {
        // Failed to open connection, so close the quic stream
        auto stream = tcp.data<quic::Stream>();
        if (stream)
            stream->close(code(tunnel::tunnel_error::TCP_FAILED));
        tcp.close();
    });
    tcp.on<uvw::DataEvent>(tunnel::on_outgoing_data);
}

}
