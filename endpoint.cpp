#include "endpoint.h"
#include "server.h"
#include "client.h"

#include <iostream>

#include <oxenmq/hex.h>

#include "log.h"

namespace quic {

Endpoint::Endpoint(std::optional<Address> addr, uv_loop_t* loop) {
    // Create and bind the UDP socket. We can't use libuv's UDP socket here because it doesn't
    // give us the ability to set up the ECN field as QUIC requires.
    auto fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1)
        throw std::runtime_error{"Failed to open socket: "s + strerror(errno)};

    if (addr) {
        assert(addr->sockaddr_size() == sizeof(sockaddr_in)); // FIXME: IPv4-only for now
        auto rv = bind(fd, *addr, addr->sockaddr_size());
        if (rv == -1)
            throw std::runtime_error{"Failed to bind UDP socket to " + addr->to_string() + ": " + strerror(errno)};
    }

    // Get our address via the socket in case `addr` is using anyaddr/anyport.
    sockaddr_any sa;
    socklen_t salen = sizeof(sa);
    // FIXME: if I didn't call bind above then do I need to call bind() before this (with anyaddr/anyport)?
    getsockname(fd, &sa.sa, &salen);
    assert(salen == sizeof(sockaddr_in)); // FIXME: IPv4-only for now
    local = {&sa, salen};
    Debug("Bound to ", local, addr ? "" : " (auto-selected)");

    // Set up the socket to provide us with incoming ECN (IP_TOS) info
    // NB: This is for IPv4; on AF_INET6 this would be IPPROTO_IPV6, IPV6_RECVTCLASS
    if (uint8_t want_tos = 1;
            -1 == setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &want_tos, static_cast<socklen_t>(sizeof(want_tos))))
        throw std::runtime_error{"Failed to set ECN on socket: "s + strerror(errno)};

    // Wire up our recv buffer structures into what recvmmsg() wants
    buf.resize(max_buf_size * msgs.size());
    for (size_t i = 0; i < msgs.size(); i++) {
        auto& iov = msgs_iov[i];
        iov.iov_base = buf.data() + max_buf_size * i;
        iov.iov_len = max_buf_size;
#ifdef LOKINET_HAVE_RECVMMSG
        auto& mh = msgs[i].msg_hdr;
#else
        auto& mh = msgs[i];
#endif
        mh.msg_name = &msgs_addr[i];
        mh.msg_namelen = sizeof(msgs_addr[i]);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = msgs_cmsg[i].data();
        mh.msg_controllen = msgs_cmsg[i].size();
    }

    // Let uv do its stuff
    poll.data = this;
    uv_poll_init(loop, &poll, fd);
    uv_poll_start(&poll, UV_READABLE,
            [](uv_poll_t* handle, int status, int events) {
                static_cast<Endpoint*>(handle->data)->poll_callback(status, events);
            });

    // Set up a callback every 250ms to clean up stale sockets, etc.
    expiry_timer.data = this;
    uv_timer_init(loop, &expiry_timer);
    uv_timer_start(&expiry_timer,
            [](uv_timer_t* handle) { static_cast<Endpoint*>(handle->data)->check_timeouts(); },
            250/*ms*/, 250/*ms*/);

    Debug("Created endpoint");
}

void Endpoint::poll_callback(int status, int events) {
    Debug("poll callback");

#ifdef LOKINET_HAVE_RECVMMSG
    // NB: recvmmsg is linux-specific but ought to offer some performance benefits
    int n_msg = recvmmsg(socket_fd(), msgs.data(), msgs.size(), 0, nullptr);
    if (n_msg == -1) {
        if (errno != EAGAIN && errno != ENOTCONN)
            Warn("Error recv'ing from ", local.to_string(), ": ", strerror(errno));
        return;
    }

    Debug("Recv'd ", n_msg, " messages");
    for (int i = 0; i < n_msg; i++) {
        auto& [msg_hdr, msg_len] = msgs[i];
        bstring_view data{buf.data() + i*max_buf_size, msg_len};
#else
    for (size_t i = 0; i < N_msgs; i++) {
        auto& msg_hdr = msgs[0];
        auto n_bytes = recvmsg(socket_fd(), &msg_hdr, 0);
        if (n_bytes == -1 && errno != EAGAIN && errno != ENOTCONN)
            Warn("Error recv'ing from ", local.to_string(), ": ", strerror(errno));
        if (n_bytes <= 0)
            return;
        auto msg_len = static_cast<unsigned int>(n_bytes);
        bstring_view data{buf.data(), msg_len};
#endif

        Debug("header [", msg_hdr.msg_namelen, "]: ", oxenmq::to_hex(std::string_view{reinterpret_cast<char*>(msg_hdr.msg_name), msg_hdr.msg_namelen}));

        if (!msg_hdr.msg_name || msg_hdr.msg_namelen != sizeof(sockaddr_in)) { // FIXME: IPv6 support?
            Warn("Invalid/unknown source address, dropping packet");
            continue;
        }

        Packet pkt{
            Path{local, reinterpret_cast<const sockaddr_any*>(msg_hdr.msg_name), msg_hdr.msg_namelen},
            data, ngtcp2_pkt_info{.ecn=0}};

        // Go look for the ECN header field on the incoming packet
        for (auto cmsg = CMSG_FIRSTHDR(&msg_hdr); cmsg; cmsg = CMSG_NXTHDR(&msg_hdr, cmsg)) {
            // IPv4; for IPv6 these would be IPPROTO_IPV6 and IPV6_TCLASS
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len) {
                pkt.info.ecn = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg));
            }
        }

        Debug(i, '[', pkt.path, ",ecn=0x", std::hex, pkt.info.ecn, std::dec, "]: received ", msg_len, " bytes");

        handle_packet(pkt);

#ifdef LOKINET_HAVE_RECVMMSG // Help editor's { } matching:
    }
#else
    }
#endif
}

io_result Endpoint::read_packet(const Packet& p, conns_iterator conn_it) {
    auto& [cid, conn] = *conn_it;
    auto rv = ngtcp2_conn_read_pkt(conn, p.path, &p.info,
            reinterpret_cast<const uint8_t*>(p.data.data()), p.data.size(),
            get_timestamp());

    switch (rv) {
        case NGTCP2_ERR_DRAINING:
            start_draining(conn_it);
            return {rv};
        case NGTCP2_ERR_DROP_CONN:
            delete_conn(std::move(conn_it));
            return {rv};
        case 0:
        case NGTCP2_ERR_RETRY:
            return {rv};
    };
    close_connection(std::move(conn_it), ngtcp2_err_infer_quic_transport_error_code(rv));
    return {rv};
}

void Endpoint::update_ecn() {
    if (ecn_curr != ecn_next) {
        if (-1 == setsockopt(socket_fd(), IPPROTO_IP, IP_TOS, &ecn_next, static_cast<socklen_t>(sizeof(ecn_next))))
            Warn("setsockopt failed to set IP_TOS: ", strerror(errno));

        // IPv6 version:
        //int tclass = this->ecn;
        //setsockopt(socket_fd(), IPPROTO_IPV6, IPV6_TCLASS, &tclass, static_cast<socklen_t>(sizeof(tclass)));

        ecn_curr = ecn_next;
    }
}

io_result Endpoint::send_packet(const Address& to, bstring_view data) {
    iovec msg_iov;
    msg_iov.iov_base = const_cast<std::byte*>(data.data());
    msg_iov.iov_len = data.size();

    msghdr msg{};
    msg.msg_name = &const_cast<sockaddr&>(reinterpret_cast<const sockaddr&>(to));
    msg.msg_namelen = sizeof(sockaddr_in);
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    auto fd = socket_fd();

    update_ecn();
    ssize_t nwrite = 0;
    do {
        nwrite = sendmsg(fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        Warn("sendmsg failed: ", strerror(errno));
        return {errno};
    }

    Debug("[", to.to_string(), ",ecn=0x", std::hex, ecn_curr, std::dec,
        "]: sent ", nwrite, " bytes");
    return {};
}

void Endpoint::send_version_negotiation(const version_info& vi, const Address& source) {
    std::array<std::byte, NGTCP2_MAX_PKTLEN_IPV4> buf;
    std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
    std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
    // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
    versions[0] = 0x1a2a3a4au;

    auto nwrote = ngtcp2_pkt_write_version_negotiation(
            reinterpret_cast<uint8_t*>(buf.data()), buf.size(),
            std::uniform_int_distribution<uint8_t>{0, 255}(rng),
            vi.dcid, vi.dcid_len, vi.scid, vi.scid_len, versions.data(), versions.size());
    if (nwrote < 0)
        Warn("Failed to construct version negotiation packet: ", ngtcp2_strerror(nwrote));
    if (nwrote <= 0)
        return;

    ecn_next = 0;
    send_packet(source, bstring_view{buf.data(), static_cast<size_t>(nwrote)});
}

void Endpoint::close_connection(conns_iterator cit, uint64_t code, bool application) {
    Debug("Closing connection ", cit->first);
    auto& [cid, c] = *cit;
    if (c.closing.empty()) {
        c.closing.resize(max_pkt_size_v4);
        Path path;
        ngtcp2_pkt_info pi;

        auto write_close_func = application
            ? ngtcp2_conn_write_application_close
            : ngtcp2_conn_write_connection_close;
        auto written = write_close_func(
                c,
                path,
                &pi,
                reinterpret_cast<unsigned char*>(c.closing.data()),
                c.closing.size(),
                code,
                get_timestamp());
        if (written < 0) {
            c.closing.clear();
            Warn("Failed to write connection close packet: ", ngtcp2_strerror(written));
            return;
        }
        assert(written <= (long) c.closing.size());
        c.closing.resize(written);

        // FIXME: ipv6
        assert(path.local.sockaddr_size() == sizeof(sockaddr_in));
        assert(path.remote.sockaddr_size() == sizeof(sockaddr_in));

        c.path = path;
    }
    assert(!c.closing.empty());

    ecn_next = 0;
    if (auto sent = send_packet(c.path.remote, c.closing);
            !sent) {
        Warn("Failed to send packet: ", strerror(sent.error_code), "; removing connection ", cid);
        delete_conn(cit);
        return;
    }
}

/// Puts a connection into draining mode (i.e. after getting a connection close).  This will
/// keep the connection registered for the recommended 3*Probe Timeout, during which we drop
/// packets that use the connection id and after which we will forget about it.
void Endpoint::start_draining(const conns_iterator& cit) {
    auto& [cid, conn] = *cit;
    if (conn.draining)
        return;
    conn.draining = true;
    // Recommended draining time is 3*Probe Timeout
    draining.emplace(cid, now() + ngtcp2_conn_get_pto(conn) * 3 * 1ns);
}

void Endpoint::check_timeouts() {
    auto expired = now();
    // Destroy any connections that are finished draining
    while (!draining.empty() && draining.front().second < expired) {
        if (auto it = conns.find(draining.front().first); it != conns.end())
            delete_conn(std::move(it));
        draining.pop();
    }

    uint64_t expired_ts = std::chrono::duration_cast<std::chrono::nanoseconds>(
            expired.time_since_epoch()).count();
    for (auto it = conns.begin(); it != conns.end(); ++it) {
        if (ngtcp2_conn_get_idle_expiry(it->second) >= expired_ts)
            continue;
        start_draining(it);
    }
}

auto Endpoint::delete_conn(conns_iterator cit) -> conns_iterator {
    for (auto& alias_cid : cit->second.aliases)
        conn_alias.erase(alias_cid);
    return conns.erase(cit);
}

/*
static void alloc_buffer(uv_handle_t* h, size_t suggested_size, uv_buf_t* buf) {
    auto& self = *static_cast<Server*>(h->data);
    if (self.buffer.size() < suggested_size)
        self.buffer.resize(suggested_size);
    buf->base = self.buffer.data();
    buf->len = self.buffer.size();
}
*/


}
