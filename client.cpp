
#include "client.h"
#include "log.h"

namespace quic {

// Cranks a value to 11, i.e. set it to its maximum
template <typename T>
void crank_to_eleven(T& val) { val = std::numeric_limits<T>::max(); }

static std::array<uint8_t, 32> null_secret{};
static std::array<uint8_t, 16> null_iv{};
static std::array<uint8_t, 4096> null_data{};

Client::Client(Address remote, uv_loop_t* loop_, std::optional<Address> local_)
        : Endpoint{std::move(local_), loop_} {

    // Our UDP socket is now set up, so now we initiate contact with the remote QUIC
    Path path{local, remote};
    Debug("Connecting to ", remote);

    // TODO: need timers for:
    //
    // - timeout (to disconnect if idle for too longer)
    //
    // - probably don't need for lokinet tunnel: change local addr -- attempts to re-bind the local socket
    //
    // - key_update_timer
    //
    // - delay_stream_timer


    auto local_cid = ConnectionID::random(rng);
    auto [it, ins] = conns.emplace(std::piecewise_construct,
            std::forward_as_tuple(local_cid),
            std::forward_as_tuple(*this, local_cid, path));
    assert(ins);
    auto& conn = it->second;

    // FIXME: likely need to move this crap info connection.cpp, or maybe a "null_crypto.cpp"?
    ngtcp2_crypto_ctx null_crypto{};
    crank_to_eleven(null_crypto.max_encryption);
    crank_to_eleven(null_crypto.max_decryption_failure);

    Debug("set crypto ctx");

    ngtcp2_crypto_aead_ctx null_aead_ctx{};
    ngtcp2_crypto_aead retry_aead{0, 16}; // FIXME: 16 overhead is for AES-128-GCM AEAD, but do we need it?
    ngtcp2_crypto_cipher_ctx null_cipher_ctx{};

    ngtcp2_conn_set_initial_crypto_ctx(conn, &null_crypto);
    ngtcp2_conn_install_initial_key(conn, &null_aead_ctx, null_iv.data(), &null_cipher_ctx, &null_aead_ctx, null_iv.data(), &null_cipher_ctx, null_iv.size());
    ngtcp2_conn_set_retry_aead(conn, &retry_aead, &null_aead_ctx);
    ngtcp2_conn_set_crypto_ctx(conn, &null_crypto);
    ngtcp2_conn_install_rx_handshake_key(conn, &null_aead_ctx, null_iv.data(), null_iv.size(), &null_cipher_ctx);
    ngtcp2_conn_install_tx_handshake_key(conn, &null_aead_ctx, null_iv.data(), null_iv.size(), &null_cipher_ctx);
    ngtcp2_conn_install_rx_key(conn, null_secret.data(), null_secret.size(), &null_aead_ctx, null_iv.data(), null_iv.size(), &null_cipher_ctx);
    ngtcp2_conn_install_tx_key(conn, null_secret.data(), null_secret.size(), &null_aead_ctx, null_iv.data(), null_iv.size(), &null_cipher_ctx);

    auto x = ngtcp2_conn_get_max_data_left(conn);
    Debug("mdl = ", x);

    conn.flush_streams();

    Debug("Opening bidi stream");
    int64_t stream_id;
    if (auto rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
            rv != 0) {
        Debug("Opening bidi stream failed: ", ngtcp2_strerror(rv));
        assert(rv == NGTCP2_ERR_STREAM_ID_BLOCKED);
    }
    else { Debug("Opening bidi stream good"); }
}

void Client::handle_packet(const Packet& p) {
    version_info vi;
    auto rv = ngtcp2_pkt_decode_version_cid(&vi.version, &vi.dcid, &vi.dcid_len, &vi.scid, &vi.scid_len,
            u8data(p.data), p.data.size(), NGTCP2_MAX_CIDLEN);
    if (rv == 1) // 1 means Version Negotiation should be sent
        return send_version_negotiation(vi, p.path.remote);
    else if (rv != 0) {
        Warn("QUIC packet header decode failed: ", ngtcp2_strerror(rv));
        return;
    }

    if (vi.dcid_len > ConnectionID::max_size()) {
        Warn("Internal error: destination ID is longer than should be allowed");
        return;
    }

}

}
