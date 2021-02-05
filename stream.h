#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string_view>
#include <type_traits>
#include <vector>

namespace quic {

using bstring_view = std::basic_string_view<std::byte>;

// Shortcut for a const-preserving `reinterpret_cast`ing c.data() from a std::byte to a uint8_t
// pointer, because we need it all over the place in the ngtcp2 API and I'd rather deal with
// std::byte's out here for type safety.
template <typename Container, typename = std::enable_if_t<sizeof(typename std::remove_reference_t<Container>::value_type) == sizeof(uint8_t)>>
inline auto* u8data(Container&& c) {
    using u8_sameconst_t = std::conditional_t<std::is_const_v<std::remove_pointer_t<decltype(c.data())>>,
          const uint8_t, uint8_t>;
    return reinterpret_cast<u8_sameconst_t*>(c.data());
}

// Storage for an established stream (a single connection has multiple streams): we have a
// fixed-sized ring buffer for holding outgoing data, and a callback to invoke on received data.
struct Stream {
    // Callback to invoke when we receive some incoming data; there's no particular guarantee on the
    // size of the data, just that this will always be called in sequential order.
    std::function<void(bstring_view data)> callback;

    // Returns the number of free bytes available in the outgoing stream data buffer
    size_t available() const;

    // Returns the number of bytes of the buffer that have not yet been acked.  (This includes both
    // sent and unsent bytes).
    size_t unacked() const;

    // Returns the number of bytes of the buffer that have not yet been sent.
    size_t unsent() const;

    // Append bytes to the outgoing stream data buffer.  Returns the number of appended bytes (which
    // will be less than the total provided if the provided data is larger than `available()`).
    size_t append(bstring_view data);

    // Try to append the given bytes to the outgoing stream data buffer if there is sufficient
    // space.  Returns true if successful, false (without appending anything) if there is
    // insufficient space.
    bool try_append(bstring_view data);

    // Called to advance the number of acknowledged bytes (freeing up that space in the buffer for
    // appending data).
    void acknowledge(size_t bytes);

    // Returns a view into unwritten stream data.  This returns two optional string_views: if there
    // is no pending data to write then both are empty; if the data to write does not wrap the
    // buffer then the second will be empty and the first contains the data; if it wraps then both
    // are set and the second buffer data immediately follows the first buffer data.  After writing
    // any of the provided data you should call `wrote()` to signal how much data you consumed.
    std::array<std::optional<bstring_view>, 2> pending();

    // Called to signal that bytes have been written and should now be considered sent (but still
    // unacknowledged), thereby advancing the initial data position returned by the next `pending()`
    // call.  Should typically be called after `pending()` to signal how much of the pending data
    // was actually used.
    void wrote(size_t bytes);

private:
    // ring buffer of outgoing stream data that has not yet been acknowledged.  This cannot be
    // resized once used as ngtcp2 will have pointers into the data.
    std::vector<std::byte> buffer{65536}; // FIXME -- configurable size?

    // Offset of the next unused byte of the buffer
    size_t wpos{0};

    // Offset of the first unsent byte of the buffer
    size_t rpos{0};

    // Offset of the first unacknowledged byte (i.e. bytes in [ack_pos, pos) are sent but not yet
    // acknowledged).
    size_t ack_pos{0};

    // Used buffer size
    size_t size{0};
};

}
