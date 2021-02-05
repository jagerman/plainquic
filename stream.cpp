#include "stream.h"
#include <cassert>

namespace quic {

size_t Stream::available() const {
    return buffer.size() - size;
}

bool Stream::try_append(bstring_view data) {
    size_t avail = available();
    if (avail < data.size())
        return false;

    size_t copy_size = data.size();
    if (wpos + data.size() > buffer.size()) {
        // We are wrapping
        size_t prewrap = buffer.size() - wpos;
        std::copy(data.begin(), data.begin() + prewrap, buffer.begin() + wpos);
        std::copy(data.begin() + prewrap, data.end(), buffer.begin());
    } else {
        std::copy(data.begin(), data.end(), buffer.begin() + wpos);
    }
    wpos = (wpos + data.size()) % buffer.size();
    size += data.size();
    return true;
}
size_t Stream::append(bstring_view data) {
    size_t avail = available();
    if (data.size() > avail)
        data.remove_suffix(data.size() - avail);
    [[maybe_unused]] bool appended = try_append(data);
    assert(appended);
    return data.size();
}

size_t Stream::unsent() const {
    if (rpos <= wpos)
        return wpos - rpos;
    return buffer.size() + wpos - rpos; // Unsent segment wraps around the end
}

size_t Stream::unacked() const {
    if (ack_pos <= wpos)
        return wpos - ack_pos;
    // Otherwise ack_pos > wpos which means the unacked part wraps the buffer
    return buffer.size() + wpos - ack_pos;
}

void Stream::acknowledge(size_t bytes) {
    assert(bytes <= size);
    assert(bytes <= unacked());
    ack_pos = (ack_pos + bytes) % buffer.size();
    size -= bytes;
}

std::array<std::optional<bstring_view>, 2> Stream::pending() {
    std::array<std::optional<bstring_view>, 2> bufs;
    if (rpos < wpos) {
        bufs[0].emplace(buffer.data() + rpos, wpos - rpos);
    } else if (rpos > wpos) { // wrapping
        bufs[0].emplace(buffer.data() + rpos, buffer.size() - rpos);
        bufs[1].emplace(buffer.data(), wpos);
    }
    return bufs;
}

void Stream::wrote(size_t bytes) {
    assert(bytes <= size);
    assert(bytes <= unsent());
    rpos = (rpos + bytes) % buffer.size();
}

}
