#include "connection.h"
#include "server.h"
#include "client.h"

#include <cassert>
#include <cstring>
#include <iostream>

#include "log.h"

#include <oxenmq/hex.h>


namespace quic {

ConnectionID::ConnectionID(const uint8_t* cid, size_t length) {
    assert(length <= max_size());
    datalen = length;
    std::memmove(data, cid, datalen);
}

std::ostream& operator<<(std::ostream& o, const ConnectionID& c) {
    return o << oxenmq::to_hex(c.data, c.data + c.datalen);
}

namespace {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
    int client_initial(ngtcp2_conn* conn, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int recv_crypto_data(ngtcp2_conn* conn, ngtcp2_crypto_level crypto_level, uint64_t offset, const uint8_t* data, size_t datalen, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int encrypt(
            uint8_t* dest,
            const ngtcp2_crypto_aead* aead, const ngtcp2_crypto_aead_ctx* aead_ctx,
            const uint8_t* plaintext, size_t plaintextlen,
            const uint8_t* nonce, size_t noncelen,
            const uint8_t* ad, size_t adlen) {
        Debug();
        // FIXME
        return 0;
    }
    int decrypt(
            uint8_t* dest,
            const ngtcp2_crypto_aead* aead, const ngtcp2_crypto_aead_ctx* aead_ctx,
            const uint8_t* plaintext, size_t plaintextlen,
            const uint8_t* nonce, size_t noncelen,
            const uint8_t* ad, size_t adlen) {
        Debug();
        // FIXME
        return 0;
    }
    int hp_mask(
            uint8_t* dest,
            const ngtcp2_crypto_cipher* hp, const ngtcp2_crypto_cipher_ctx* hp_ctx,
            const uint8_t* sample) {
        Debug();
        // FIXME
        return 0;
    }
    int recv_stream_data(
            ngtcp2_conn* conn,
            uint32_t flags,
            int64_t stream_id,
            uint64_t offset,
            const uint8_t* data, size_t datalen,
            void* user_data,
            void* stream_user_data) {
        Debug();
        // FIXME
        return 0;
    }

    // Do we need acked_stream_data_offset?

    int stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int stream_close(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data) {
        Debug();
        // FIXME
        return 0;
    }

    // (client only)
    int recv_retry(ngtcp2_conn* conn, const ngtcp2_pkt_hd* hd, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int extend_max_local_streams_bidi(ngtcp2_conn* conn, uint64_t max_streams, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int rand(
            uint8_t* dest, size_t destlen,
            const ngtcp2_rand_ctx* rand_ctx,
            [[maybe_unused]] ngtcp2_rand_usage usage) {
        Debug();
        auto& rng = *static_cast<std::mt19937_64*>(rand_ctx->native_handle);
        random_bytes(dest, destlen, rng);
        return 0;
    }
    int get_new_connection_id(
            ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int remove_connection_id(ngtcp2_conn* conn, const ngtcp2_cid* cid, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int update_key(
            ngtcp2_conn* conn, uint8_t* rx_secret, uint8_t* tx_secret,
            ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
            ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
            const uint8_t* current_rx_secret, const uint8_t* current_tx_secret,
            size_t secretlen, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int handshake_confirmed(ngtcp2_conn* conn, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int recv_new_token(ngtcp2_conn* conn, const ngtcp2_vec* token, void* user_data) {
        Debug();
        // FIXME
        return 0;
    }
    int stream_reset(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t final_size,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data) {
        Debug();
        // FIXME
        return 0;
    }
#pragma GCC diagnostic pop
}

#ifndef NDEBUG
extern "C" inline void debug_logger([[maybe_unused]] void* user_data, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}
#endif


bool Connection::send() {
    if (!send_buffer.empty()) {
        auto rv = endpoint.send_packet(path.remote, send_buffer);
        if (rv.error_code == EAGAIN || rv.error_code == EWOULDBLOCK) {
            uv_poll_start(&wpoll, UV_WRITABLE,
                    [](uv_poll_t* handle, int status, int events) {
                        static_cast<Connection*>(handle->data)->send();
                    });
            wpoll_active = true;
            return false;
        } else if (!rv) {
            // FIXME: disconnect here
            return false;
        }
    }

    // We succeeded
    // FIXME: check and send other pending streams
    //
    // FIXME: schedule retransmit?
    return true;
}


std::pair<ngtcp2_settings, ngtcp2_callbacks> Connection::init(Endpoint& ep) {
    io_trigger.reset(new uv_async_t);
    io_trigger->data = this;
    uv_async_init(ep.loop, io_trigger.get(),
            [](uv_async_t* a) { static_cast<Connection*>(a->data)->io_callback(); });

    wpoll.data = this;
    uv_poll_init(ep.loop, &wpoll, ep.socket_fd());
    // Don't start wpoll now; we only start it up temporarily when a send blocks.

    auto result = std::pair<ngtcp2_settings, ngtcp2_callbacks>{};
    auto& [settings, cb] = result;
    cb.recv_crypto_data = recv_crypto_data;
    cb.encrypt = encrypt;
    cb.decrypt = decrypt;
    cb.hp_mask = hp_mask;
    cb.recv_stream_data = recv_stream_data;
    cb.stream_close = stream_close;
    cb.rand = rand;
    cb.get_new_connection_id = get_new_connection_id;
    cb.remove_connection_id = remove_connection_id;
    cb.update_key = update_key;
    cb.stream_reset = stream_reset;

    ngtcp2_settings_default(&settings);

#ifndef NDEBUG
    settings.log_printf = debug_logger;
#endif
    settings.initial_ts = get_timestamp();
    // FIXME: IPv6
    settings.max_udp_payload_size = NGTCP2_MAX_PKTLEN_IPV4;
    settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;
    //settings.initial_rtt = ???; # NGTCP2's default is 333ms

    auto& tparams = settings.transport_params;
    // Max send buffer for a stream we initiate:
    tparams.initial_max_stream_data_bidi_local = 64*1024;
    // Max send buffer for a stream the remote initiated:
    tparams.initial_max_stream_data_bidi_remote = 64*1024;
    // Max *cumulative* streams we support on a connection:
    tparams.initial_max_streams_bidi = 100;
    tparams.initial_max_streams_uni = 0;
    tparams.max_idle_timeout = std::chrono::milliseconds(IDLE_TIMEOUT).count();
    tparams.active_connection_id_limit = 7;

    Debug("Done basic connection initialization");

    return result;
}


Connection::Connection(Server& s, const ConnectionID& scid, ngtcp2_pkt_hd& header, const Path& path)
        : endpoint{s}, dest_cid{header.scid.data, header.scid.datalen}, path{path} {

    auto [settings, cb] = init(s);

    cb.recv_client_initial = recv_client_initial;
    cb.stream_open = stream_open;

    auto& tparams = settings.transport_params;
    tparams.original_dcid = scid;
    settings.token = header.token;
    random_bytes(std::begin(tparams.stateless_reset_token), sizeof(tparams.stateless_reset_token), s.rng);
    tparams.stateless_reset_token_present = 1;

    ngtcp2_conn* connptr;
    if (auto rv = ngtcp2_conn_server_new(&connptr, &dest_cid, &scid, path, header.version,
                &cb, &settings, nullptr /*default mem allocator*/, this);
            rv != 0)
        throw std::runtime_error{
            "Failed to initialize server connection: "s + ngtcp2_strerror(rv)};
    conn.reset(connptr);

    Debug("Created new server conn ", scid);
    
}


Connection::Connection(Client& c, const Path& path)
        : endpoint{c}, dest_cid{ConnectionID::random(c.rng)}, path{path} {

    auto [settings, cb] = init(c);

    cb.client_initial = client_initial;
    cb.recv_retry = recv_retry;
    cb.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
    cb.handshake_confirmed = handshake_confirmed;
    cb.recv_new_token = recv_new_token;

    ngtcp2_conn* connptr;
    constexpr uint32_t version = 0xff000020u;
    static_assert(version >= NGTCP2_PROTO_VER_MIN && version <= NGTCP2_PROTO_VER_MAX);
    auto scid = ConnectionID::random(c.rng);

    if (auto rv = ngtcp2_conn_client_new(&connptr, &dest_cid, &scid, path, version,
                &cb, &settings, nullptr, this);
            rv != 0)
        throw std::runtime_error{
            "Failed to initialize client connection: "s + ngtcp2_strerror(rv)};
    conn.reset(connptr);

    Debug("Created new client conn ", scid);
}


void Connection::io_callback() {
    Debug();
    // FIXME
}

void Connection::on_read(bstring_view data) {
    Debug("data size: ", data.size());
    // FIXME
}

}
