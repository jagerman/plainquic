#include "connection.h"
#include "server.h"
#include "client.h"

#include <cassert>
#include <cstring>
#include <iostream>

#include "log.h"

#include <oxenmq/hex.h>

// DEBUG
extern "C" {
#include "../ngtcp2_conn.h"
}


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

    constexpr int FAIL = NGTCP2_ERR_CALLBACK_FAILURE;

    int client_initial(ngtcp2_conn* conn_, void* user_data) {
        Debug("######################", __func__);

        // Initialization the connection and send our transport parameters to the server.  This will
        // put the connection into NGTCP2_CS_CLIENT_WAIT_HANDSHAKE state.
        return static_cast<Connection*>(user_data)->init_client();
    }
    int recv_client_initial(ngtcp2_conn* conn_, const ngtcp2_cid* dcid, void* user_data) {
        Debug("######################", __func__);


        // New incoming connection from a client: our server connection starts out here in state
        // NGTCP2_CS_SERVER_INITIAL, but we should immediately get into recv_crypto_data because the
        // initial client packet should contain the client's transport parameters.

        auto& conn = *static_cast<Connection*>(user_data);
        assert(conn_ == conn.conn.get());

        if (0 != conn.setup_server_crypto_initial())
            return FAIL;

        return 0;
    }
    int recv_crypto_data(ngtcp2_conn* conn_, ngtcp2_crypto_level crypto_level, uint64_t offset, const uint8_t* rawdata, size_t rawdatalen, void* user_data) {
        std::basic_string_view data{rawdata, rawdatalen};
        Debug("\e[32;1mReceiving crypto data @ level ", crypto_level, "\e[0m ", buffer_printer{data});

        auto& conn = *static_cast<Connection*>(user_data);
        switch (crypto_level) {
            case NGTCP2_CRYPTO_LEVEL_EARLY:
                // We don't currently use or support 0rtt
                Warn("Invalid EARLY crypto level");
                return FAIL;

            case NGTCP2_CRYPTO_LEVEL_INITIAL:
                // "Initial" level means we are still handshaking; if we are server then we receive
                // the client's transport params (sent in client_initial, above) and blast ours
                // back.  If we are a client then getting here means we received a response from the
                // server, which is that returned server transport params.

                if (auto rv = conn.recv_initial_crypto(data); rv != 0)
                    return rv;

                if (ngtcp2_conn_is_server(conn)) {
                    if (auto rv = conn.send_magic(NGTCP2_CRYPTO_LEVEL_INITIAL); rv != 0)
                        return rv;
                    if (auto rv = conn.send_transport_params(NGTCP2_CRYPTO_LEVEL_HANDSHAKE); rv != 0)
                        return rv;
                }

                break;

            case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:

                if (!ngtcp2_conn_is_server(conn)) {
                    if (auto rv = conn.recv_transport_params(data); rv != 0)
                        return rv;
                    // At this stage of the protocol with TLS the client sends back TLS info so that
                    // the server can install our rx key; we have to send *something* back to invoke
                    // the server's HANDSHAKE callback (so that it knows handshake is complete) so
                    // sent the magic again.
                    if (auto rv = conn.send_magic(NGTCP2_CRYPTO_LEVEL_HANDSHAKE); rv != 0)
                        return rv;
                } else {
                    // Check that we received the above as expected
                    if (data != handshake_magic) {
                        Warn("Invalid handshake crypto frame from client: did not find expected magic");
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    }
                }

                conn.complete_handshake();
                break;

            case NGTCP2_CRYPTO_LEVEL_APPLICATION:
                //if (!conn.init_tx_key())
                //    return FAIL;
                break;

            default:
                Warn("Unhandled crypto_level ", crypto_level);
                return FAIL;
        }
        conn.io_ready();
        return 0;
    }
    int encrypt(
            uint8_t* dest,
            const ngtcp2_crypto_aead* aead, const ngtcp2_crypto_aead_ctx* aead_ctx,
            const uint8_t* plaintext, size_t plaintextlen,
            const uint8_t* nonce, size_t noncelen,
            const uint8_t* ad, size_t adlen) {
        Debug("######################", __func__);
        Debug("Lengths: ", plaintextlen, "+", noncelen, "+", adlen);
        if (dest != plaintext)
            std::memmove(dest, plaintext, plaintextlen);
        return 0;
    }
    int decrypt(
            uint8_t* dest,
            const ngtcp2_crypto_aead* aead, const ngtcp2_crypto_aead_ctx* aead_ctx,
            const uint8_t* ciphertext, size_t ciphertextlen,
            const uint8_t* nonce, size_t noncelen,
            const uint8_t* ad, size_t adlen) {
        Debug("######################", __func__);
        Debug("Lengths: ", ciphertextlen, "+", noncelen, "+", adlen);
        if (dest != ciphertext)
            std::memmove(dest, ciphertext, ciphertextlen);
        return 0;
    }
    int hp_mask(
            uint8_t* dest,
            const ngtcp2_crypto_cipher* hp, const ngtcp2_crypto_cipher_ctx* hp_ctx,
            const uint8_t* sample) {
        Debug("######################", __func__);
        memset(dest, 0, NGTCP2_HP_MASKLEN);
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
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }

    // Do we need acked_stream_data_offset?  (Yes! need it to free the used buffer space)

    int stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }
    int stream_close(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }

    // (client only)
    int recv_retry(ngtcp2_conn* conn, const ngtcp2_pkt_hd* hd, void* user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }
    /*
    int extend_max_local_streams_bidi(ngtcp2_conn* conn, uint64_t max_streams, void* user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }
    */
    int rand(
            uint8_t* dest, size_t destlen,
            const ngtcp2_rand_ctx* rand_ctx,
            [[maybe_unused]] ngtcp2_rand_usage usage) {
        Debug("######################", __func__);
        auto& rng = *static_cast<std::mt19937_64*>(rand_ctx->native_handle);
        random_bytes(dest, destlen, rng);
        return 0;
    }
    int get_new_connection_id(
            ngtcp2_conn* conn_, ngtcp2_cid* cid_, uint8_t* token, size_t cidlen, void* user_data) {
        Debug("######################", __func__);

        auto& conn = *static_cast<Connection*>(user_data);
        auto cid = conn.make_alias_id(cidlen);
        assert(cid.datalen == cidlen);
        *cid_ = cid;

        conn.endpoint.make_stateless_reset_token(cid, token);
        Debug("make stateless reset token ", oxenmq::to_hex(token, token + NGTCP2_STATELESS_RESET_TOKENLEN));

        return 0;
    }
    int remove_connection_id(ngtcp2_conn* conn, const ngtcp2_cid* cid, void* user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }
    int update_key(
            ngtcp2_conn* conn, uint8_t* rx_secret, uint8_t* tx_secret,
            ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
            ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
            const uint8_t* current_rx_secret, const uint8_t* current_tx_secret,
            size_t secretlen, void* user_data) {
        // This is a no-op since we don't encrypt anything in the first place
        return 0;
    }
    /*
    int recv_new_token(ngtcp2_conn* conn, const ngtcp2_vec* token, void* user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
        // FIXME
        return 0;
    }
    */
    int stream_reset(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t final_size,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data) {
        Debug("######################", __func__);
        Error("FIXME UNIMPLEMENTED ", __func__);
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


io_result Connection::send() {
    assert(send_buffer_size <= send_buffer.size());
    io_result rv{};
    bstring_view send_data{send_buffer.data(), send_buffer_size};

    if (!send_data.empty()) {
        Debug("Sending packet: ", buffer_printer{send_data});
        rv = endpoint.send_packet(path.remote, send_data, send_pkt_info.ecn);
        if (rv.blocked()) {
            uv_poll_start(&wpoll, UV_WRITABLE,
                    [](uv_poll_t* handle, int status, int events) {
                        static_cast<Connection*>(handle->data)->send();
                    });
            wpoll_active = true;
        } else if (!rv) {
            // FIXME: disconnect here?
            Warn("packet send failed: ", rv.str());
        }
    }
    return rv;

    // We succeeded
    //
    // FIXME2: probably don't want to do these things *here*, because this is called from the stream
    // checking code.
    //
    // FIXME: check and send other pending streams
    //
    // FIXME: schedule retransmit?
    //return true;
}


std::tuple<ngtcp2_settings, ngtcp2_transport_params, ngtcp2_callbacks> Connection::init(Endpoint& ep) {
    Debug("loop: ", ep.loop);
    io_trigger.reset(new uv_async_t);
    io_trigger->data = this;
    uv_async_init(ep.loop, io_trigger.get(),
            [](uv_async_t* a) { static_cast<Connection*>(a->data)->io_callback(); });

    wpoll.data = this;
    uv_poll_init(ep.loop, &wpoll, ep.socket_fd());
    // Don't start wpoll now; we only start it up temporarily when a send blocks.

    auto result = std::tuple<ngtcp2_settings, ngtcp2_transport_params, ngtcp2_callbacks>{};
    auto& [settings, tparams, cb] = result;
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

    ngtcp2_transport_params_default(&tparams);

    // Max send buffer for a stream we initiate:
    tparams.initial_max_stream_data_bidi_local = 64*1024;
    // Max send buffer for a stream the remote initiated:
    tparams.initial_max_stream_data_bidi_remote = 64*1024;
    // Max *cumulative* streams we support on a connection:
    tparams.initial_max_streams_bidi = 100;
    tparams.initial_max_streams_uni = 0;
    tparams.max_idle_timeout = std::chrono::nanoseconds(IDLE_TIMEOUT).count();
    tparams.active_connection_id_limit = 8;

    Debug("Done basic connection initialization");

    return result;
}


Connection::Connection(Server& s, const ConnectionID& base_cid_, ngtcp2_pkt_hd& header, const Path& path)
        : endpoint{s}, base_cid{base_cid_}, dest_cid{header.scid}, path{path} {

    auto [settings, tparams, cb] = init(s);

    cb.recv_client_initial = recv_client_initial;
    cb.stream_open = stream_open;

    Debug("header.type = ", +header.type);

    // ConnectionIDs are a little complicated:
    // - when a client creates a new connection to us, it creates a random source connection ID
    //   *and* a random destination connection id.  The server won't have that connection ID, of
    //   course, but we use it to recognize that we should try accepting it as a new connection.
    // - When we talk to the client we use the random source connection ID that it generated as our
    //   destination connection ID.
    // - We choose our own source ID, however: we *don't* use the random one the client picked for
    //   us.  Instead we generate a random one and sent it back as *our* source connection ID in the
    //   reply to the client.
    // - the client still needs to match up that reply with that request, and so we include the
    //   destination connection ID that the client generated for us in the transport parameters as
    //   the original_dcid: this lets the client match up the request, after which it can't promptly
    //   forget about it and start using the source CID that we gave it.
    //
    // So, in other words, the conversation goes like this:
    // - Client: [SCID:clientid, DCID:randomid, TRANSPORT_PARAMS]
    // - Server: [SCID:serverid, DCID:clientid TRANSPORT_PARAMS(origid=randomid)]
    //
    // - For the client, .base_cid={clientid} and .dest_cid={randomid} initially but gets updated to
    // .dest_cid={serverid} when we hear back from the server.
    // - For the server, .base_cid={serverid} and .dest_cid={clientid}

    tparams.original_dcid = header.dcid;

    Debug("original_dcid is now set to ", ConnectionID(tparams.original_dcid));


    settings.token = header.token;

    // FIXME is this required?
    random_bytes(std::begin(tparams.stateless_reset_token), sizeof(tparams.stateless_reset_token), s.rng);
    tparams.stateless_reset_token_present = 1;

    ngtcp2_conn* connptr;
    Debug("server_new, path=", path);
    if (auto rv = ngtcp2_conn_server_new(&connptr, &dest_cid, &base_cid, path, header.version,
                &cb, &settings, &tparams, nullptr /*default mem allocator*/, this);
            rv != 0)
        throw std::runtime_error{
            "Failed to initialize server connection: "s + ngtcp2_strerror(rv)};
    conn.reset(connptr);

    Debug("Created new server conn ", base_cid);
}


Connection::Connection(Client& c, const ConnectionID& scid, const Path& path)
        : endpoint{c}, base_cid{scid}, dest_cid{ConnectionID::random(c.rng)}, path{path} {

    auto [settings, tparams, cb] = init(c);

    cb.client_initial = client_initial;
    cb.recv_retry = recv_retry;
    //cb.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
    //cb.recv_new_token = recv_new_token;

    ngtcp2_conn* connptr;

    if (auto rv = ngtcp2_conn_client_new(&connptr, &dest_cid, &scid, path, NGTCP2_PROTO_VER_V1,
                &cb, &settings, &tparams, nullptr, this);
            rv != 0)
        throw std::runtime_error{
            "Failed to initialize client connection: "s + ngtcp2_strerror(rv)};
    conn.reset(connptr);

    Debug("Created new client conn ", scid);
}


void Connection::io_ready() {
    uv_async_send(io_trigger.get());
}

void Connection::io_callback() {
    Debug(__func__);
    flush_streams();
    Debug("done ", __func__);
}

void Connection::on_read(bstring_view data) {
    Debug("FIXME UNIMPLEMENTED ", __func__, ", data size: ", data.size());
    // FIXME
}

void Connection::flush_streams() {
    // conn, path, pi, dest, destlen, and ts
    std::optional<uint64_t> ts;

    auto add_stream_data = [&](int64_t stream_id, const ngtcp2_vec* datav, size_t datalen) {
        std::array<ngtcp2_ssize, 2> result;
        auto& [nwrite, consumed] = result;
        if (!ts) ts = get_timestamp();

        nwrite = ngtcp2_conn_writev_stream(
                conn.get(), &path.path, &send_pkt_info,
                u8data(send_buffer),
                send_buffer.size(),
                &consumed,
                NGTCP2_WRITE_STREAM_FLAG_MORE,
                stream_id,
                datav, datalen,
                *ts);
        return result;
    };

    auto send_packet = [&](auto nwrite) -> bool {
        send_buffer_size = nwrite;
        Debug("Sending ", send_buffer_size, "B packet");

        // FIXME: update remote addr? ecn?
        auto sent = send();
        if (sent.blocked()) {
            // FIXME: somewhere (maybe here?) should be setting up a write poll so that, once
            // writing becomes available again (and the pending packet gets sent), we get back here.
            // FIXME 2: I think this is already done by send() itself.
            return false;
        }
        send_buffer_size = 0;
        if (!sent) {
            Warn("I/O error while trying to send packet: ", sent.str());
            // FIXME: disconnect?
            return false;
        }
        Debug("packet away!");
        return true;
    };

    for (auto& [stream_id, stream] : streams) {
        auto bufs = stream.pending();
        if (!bufs[0]) continue;
        std::array<ngtcp2_vec, 2> vecs;
        vecs[0].base = const_cast<uint8_t*>(u8data(*bufs[0]));
        vecs[0].len = bufs[0]->length();
        if (bufs[1]) {
            vecs[1].base = const_cast<uint8_t*>(u8data(*bufs[1]));
            vecs[1].len = bufs[1]->length();
        }

        auto [nwrite, consumed] = add_stream_data(stream_id, vecs.data(), bufs[1] ? 2 : 1);
        Debug("add_stream_data for stream ", stream_id, " returned [", nwrite, ",", consumed, "]");

        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            Debug("consumed ", consumed, " bytes from stream ", stream_id, " and have space left");
            stream.wrote(consumed);
            continue;
        } else if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            Debug("cannot add to stream ", stream_id, " right now: stream is blocked");
            continue;
        } else if (nwrite < 0) {
            assert(consumed <= 0);
            Warn("Error writing to stream ", stream_id, ": ", ngtcp2_strerror(nwrite));
            return;
        } else if (nwrite == 0) {
            // FIXME: 
            Debug("Unable to continue stream writing: we are congested");
            return;
        }

        if (consumed >= 0) {
            Debug("consumed ", consumed, " bytes from stream ", stream_id);
            stream.wrote(consumed);
        }

        Debug("Sending stream data packet");
        if (!send_packet(nwrite))
            return;
    }

    // Now try more with stream id -1 and no data: this will take care of initial handshake packets,
    // and should finish off any partially-filled packet from above.
    for (;;) {
        auto [nwrite, consumed] = add_stream_data(-1, nullptr, 0);
        Debug("add_stream_data for non-stream returned [", nwrite, ",", consumed, "]");
        assert(consumed <= 0);
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            Debug("Writing non-stream data, and have space left");
            continue;
        } else if (nwrite < 0) {
            Warn("Error writing non-stream data: ", ngtcp2_strerror(nwrite));
            return;
        } else if (nwrite == 0) {
            // FIXME: Check whether this is actually possible for the -1 streamid?
            Warn("Unable to continue non-stream writing: we are congested");
            return;
        }

        Debug("Sending non-stream data packet");
        if (!send_packet(nwrite))
            return;
    }
}

Server* Connection::server() {
    return dynamic_cast<Server*>(&endpoint);
}

Client* Connection::client() {
    return dynamic_cast<Client*>(&endpoint);
}

int Connection::setup_server_crypto_initial() {
    auto* s = server();
    assert(s);
    s->null_crypto.server_initial(*this);
    io_ready();
    return 0;
}

ConnectionID Connection::make_alias_id(size_t cidlen) {
    return endpoint.add_connection_id(*this, cidlen);
}

int Connection::init_client() {
    endpoint.null_crypto.client_initial(*this);

    if (int rv = send_magic(NGTCP2_CRYPTO_LEVEL_INITIAL); rv != 0)
        return rv;
    if (int rv = send_transport_params(NGTCP2_CRYPTO_LEVEL_INITIAL); rv != 0)
        return rv;

    io_ready();
    return 0;
}

int Connection::recv_initial_crypto(std::basic_string_view<uint8_t> data) {

    if (data.substr(0, handshake_magic.size()) != handshake_magic) {
        Warn("Invalid initial crypto frame: did not find expected magic prefix");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    data.remove_prefix(handshake_magic.size());

    const bool is_server = ngtcp2_conn_is_server(*this);
    if (is_server) {
        // For a server, we receive the transport parameters in the initial packet (prepended by the
        // magic that we just removed):
        if (auto rv = recv_transport_params(data); rv != 0)
            return rv;
    } else {
        // For a client our initial crypto data should be just the magic string (the packet also
        // contains transport parameters, but they are at HANDSHAKE crypto level and so will result
        // in a second callback to handle them).
        if (!data.empty()) {
            Warn("Invalid initial crypto frame: unexpected post-magic data found");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    endpoint.null_crypto.install_rx_handshake_key(*this);
    endpoint.null_crypto.install_tx_handshake_key(*this);
    if (is_server)
        endpoint.null_crypto.install_tx_key(*this);

    return 0;
}

void Connection::complete_handshake() {
    endpoint.null_crypto.install_rx_key(*this);
    if (!ngtcp2_conn_is_server(*this))
        endpoint.null_crypto.install_tx_key(*this);
    ngtcp2_conn_handshake_completed(*this);
}

int Connection::recv_transport_params(std::basic_string_view<uint8_t> data) {
    ngtcp2_transport_params params;

    auto exttype = ngtcp2_conn_is_server(*this)
        ? NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO
        : NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS;

    auto rv = ngtcp2_decode_transport_params(&params, exttype, data.data(), data.size());
    Debug("Decode transport params ", rv == 0 ? "success" : "fail: "s + ngtcp2_strerror(rv));
    Debug("params orig dcid = ", ConnectionID(params.original_dcid));
    Debug("params init scid = ", ConnectionID(params.initial_scid));
    if (rv == 0) {
        rv = ngtcp2_conn_set_remote_transport_params(*this, &params);
        Debug("Set remote transport params ", rv == 0 ? "success" : "fail: "s + ngtcp2_strerror(rv));
    }

    if (rv != 0) {
        ngtcp2_conn_set_tls_error(*this, rv);
        return rv;
    }

    return 0;
}

// Sends our magic string at the given level.  This fixed magic string is taking the place of TLS
// parameters in full QUIC.
int Connection::send_magic(ngtcp2_crypto_level level) {
    return ngtcp2_conn_submit_crypto_data(*this, level, handshake_magic.data(), handshake_magic.size());
}

// Sends transport parameters.  `level` is expected to be INITIAL for clients (which send the
// transport parameters in the initial packet), or HANDSHAKE for servers.
int Connection::send_transport_params(ngtcp2_crypto_level level) {
    ngtcp2_transport_params tparams;
    ngtcp2_conn_get_local_transport_params(*this, &tparams);

    assert(conn_buffer.empty());
    static_assert(NGTCP2_MAX_PKTLEN_IPV4 > NGTCP2_MAX_PKTLEN_IPV6);
    conn_buffer.resize(NGTCP2_MAX_PKTLEN_IPV4);

    auto exttype = ngtcp2_conn_is_server(*this)
        ? NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS
        : NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO;

    if (ngtcp2_ssize nwrite = ngtcp2_encode_transport_params(
                u8data(conn_buffer), conn_buffer.size(), exttype, &tparams);
            nwrite >= 0) {
        assert(nwrite > 0);
        conn_buffer.resize(nwrite);
    } else {
        conn_buffer.clear();
        return nwrite;
    }
    Debug("encoded transport params: ", buffer_printer{conn_buffer});
    return ngtcp2_conn_submit_crypto_data(*this, level, u8data(conn_buffer), conn_buffer.size());
}


}
