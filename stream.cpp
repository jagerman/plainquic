#include "stream.h"
#include "connection.h"
#include "log.h"

#include <cassert>
#include <iostream>

// We use a single circular buffer with a pointer to the starting byte (denoted `á` or `ŕ`), the
// overall size, and the number of sent-but-unacked bytes (denoted `a`).  `r` denotes an unsent
// byte.
//     [       áaaaaaaarrrr       ]
//             ^                    == start
//             ------------         == size (== unacked + unsent bytes)
//             --------             == unacked_size
//                         ^        -- the next write starts here
//      ^^^^^^^            ^^^^^^^  -- unused buffer space
//
// we give ngtcp2 direct control over the unacked part of this buffer (it will let us know once the
// buffered data is no longer needed, i.e. once it is acknowledged by the remote side).
//
// The complication is that this buffer wraps, so if we write a bunch of data to the above it would
// end up looking like this:
//
//     [rrr    áaaaaaaarrrrrrrrrrr]
//
// This complicates things a bit, especially when returning the buffer to be written because we
// might have to return two separate string_views (the first would contain [rrrrrrrrrrr] and the
// second would contain [rrr]).  As soon as we pass those buffer pointers off to ngtcp2 then our
// buffer looks like:
//
//     [aaa    áaaaaaaaaaaaaaaaaaa]
//
// Once we get an acknowledgement from the other end of the QUIC connection we can move up B (the
// beginning of the buffer); for example, suppose it acknowledges the next 10 bytes and then the
// following 10; we'll have:
//
//     [aaa              áaaaaaaaa] -- first 10 acked
//     [ áa                       ] -- next 10 acked
//
// As a special case, if the buffer completely empties (i.e. all data is sent and acked) then we
// reset the starting bytes to the beginning of the buffer.

namespace quic {

std::ostream& operator<<(std::ostream& o, const StreamID& s) {
    return o << u8"Str❰" << s.id << u8"❱";
}

Stream::Stream(Connection& conn, data_callback_t data_cb, close_callback_t close_cb, size_t buffer_size)
    : conn{conn}, data_callback{std::move(data_cb)}, close_callback{std::move(close_cb)}, buffer{buffer_size}
{
}

Stream::Stream(Connection& conn, StreamID id, size_t buffer_size)
    : conn{conn}, stream_id{id}, buffer{buffer_size}
{
}

void Stream::set_buffer_size(size_t size) {
    if (used() != 0)
        throw std::runtime_error{"Cannot update buffer size while buffer is in use"};
    if (size == 0)
        size = 64*1024;
    else if (size < 2048)
        size = 2048;

    buffer.resize(size);
    buffer.shrink_to_fit();
    start = size = unacked_size = 0;
}

bool Stream::append(bstring_view data) {
    size_t avail = available();
    if (avail < data.size())
        return false;

    // When we are appending we have three cases:
    // - data doesn't fit -- we simply abort (return false, above).
    // - data fits between the buffer end and `]` -- simply append it and update size
    // - data is larger -- copy from the end up to `]`, then copy the rest into the beginning of the
    // buffer (i.e. after `[`).

    size_t copy_size = data.size();
    size_t wpos = (start + size) % buffer.size();
    if (wpos + data.size() > buffer.size()) {
        // We are wrapping
        auto data_split = data.begin() + (buffer.size() - wpos);
        std::copy(data.begin(), data_split, buffer.begin() + wpos);
        std::copy(data_split, data.end(), buffer.begin());
        Debug("Wrote ", data.size(), " bytes to buffer ranges [", wpos, ",", buffer.size(), ")+[0,", data.end()-data_split, ")");
    } else {
        // No wrap needs, it fits before the end:
        std::copy(data.begin(), data.end(), buffer.begin() + wpos);
        Debug("Wrote ", data.size(), " bytes to buffer range [", wpos, ",", wpos+data.size(), ")");
    }
    size += data.size();
    Debug("New stream buffer: ", size, "/", buffer.size(), " bytes beginning at ", start);
    conn.io_ready();
    return true;
}
size_t Stream::append_any(bstring_view data) {
    size_t avail = available();
    if (data.size() > avail)
        data.remove_suffix(data.size() - avail);
    [[maybe_unused]] bool appended = append(data);
    assert(appended);
    return data.size();
}

void Stream::acknowledge(size_t bytes) {
    // Frees bytes; e.g. acknowledge(3) changes:
    //     [  áaaaaarr  ]  to  [     áaarr  ]
    //     [aaarr     áa]  to  [ áarr       ]
    //     [  áaarrr    ]  to  [     ŕrr    ]
    //     [      áaa   ]  to  [´           ]  (i.e. empty buffer *and* reset start pos)
    //
    assert(bytes <= unacked_size && unacked_size <= size);

    Debug("Acked ", bytes, " bytes of ", unacked_size, "/", size, " unacked/total");

    unacked_size -= bytes;
    size -= bytes;
    start = size == 0 ? 0 : (start + bytes) % buffer.size(); // reset start to 0 (to reduce wrapping buffers) if empty
    if (!unblocked_callbacks.empty())
        handle_unblocked();
}

std::pair<bstring_view, bstring_view> Stream::pending() {
    std::pair<bstring_view, bstring_view> bufs;
    if (size_t rsize = unsent(); rsize > 0) {
        size_t rpos = (start + unacked_size) % buffer.size();
        if (size_t rend = rpos + rsize; rend <= buffer.size()) {
            bufs.first = {buffer.data() + rpos, rsize};
        } else { // wrapping
            bufs.first = {buffer.data() + rpos, buffer.size() - rpos};
            bufs.second = {buffer.data(), rend % buffer.size()};
        }
    }
    return bufs;
}

void Stream::when_available(unblocked_callback_t unblocked_cb) {
    unblocked_callbacks.push(std::move(unblocked_cb));
    handle_unblocked();
}

void Stream::handle_unblocked() {
    while (!unblocked_callbacks.empty() && available() > 0) {
#ifndef NDEBUG
        size_t pre_avail = available();
#endif
        bool done = unblocked_callbacks.front()(*this);
        if (done)
            unblocked_callbacks.pop();
        else
            assert(available() < pre_avail);
    }
    conn.io_ready();
}

void Stream::io_ready() { conn.io_ready(); }

void Stream::wrote(size_t bytes) {
    // Called to tell us we sent some bytes off, e.g. wrote(3) changes:
    //     [  áaarrrrrr  ]  or  [rr     áaar]
    // to:
    //     [  áaaaaarrr  ]  or  [aa     áaaa]
    assert(bytes <= unsent());
    unacked_size += bytes;
}

void Stream::close(std::optional<uint64_t> error_code) {
    Debug("Closing ", stream_id, error_code ? " immediately with code " + std::to_string(*error_code) : " gracefully");

    if (is_shutdown)
        Debug("Stream is already shutting down");
    else if (error_code) {
        is_closing = is_shutdown = true;
        ngtcp2_conn_shutdown_stream(conn, stream_id.id, *error_code);
    }
    else if (is_closing)
        Debug("Stream is already closing");
    else
        is_closing = true;

    if (is_shutdown)
        data_callback = {};

    conn.io_ready();
}

void Stream::data(std::shared_ptr<void> data) {
    user_data = std::move(data);
}

void Stream::weak_data(std::weak_ptr<void> data) {
    user_data = std::move(data);
}

}
