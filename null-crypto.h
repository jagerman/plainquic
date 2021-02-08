#pragma once

#include <array>
#include <cstdint>

#include "connection.h"

#include "ngtcp2/ngtcp2.h"

namespace quic {

// Class providing do-nothing stubs for quic crypto operations: everything over lokinet is already
// encrypted so we just no-op QUIC's built in crypto operations.
struct NullCrypto {

    NullCrypto();

    void client_initial(Connection& conn);

    void server_initial(Connection& conn);

    bool install_tx_handshake_key(Connection& conn);
    bool install_tx_key(Connection& conn);

    bool install_rx_handshake_key(Connection& conn);
    bool install_rx_key(Connection& conn);

private:
    std::array<uint8_t, 1> null_iv{};
    //std::array<uint8_t, 4096> null_data{};

    ngtcp2_crypto_ctx null_ctx{};
    ngtcp2_crypto_aead null_aead{};
    ngtcp2_crypto_aead_ctx null_aead_ctx{};
    ngtcp2_crypto_cipher_ctx null_cipher_ctx{};
};

}
