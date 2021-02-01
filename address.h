#pragma once

#include <array>
#include <cassert>
#include <cstring>
#include <string>
#include <iosfwd>

#include <ngtcp2/ngtcp2.h>

extern "C" {
#include <netinet/in.h>
#include <sys/socket.h>
}

namespace quic {

union sockaddr_any {
  sockaddr_storage storage;
  sockaddr sa;
  sockaddr_in6 in6;
  sockaddr_in in;
};


class Address {
    sockaddr_any s{};
    ngtcp2_addr a{0, &s.sa, nullptr};
public:
    Address() = default;
    Address(std::array<uint8_t, 4> ip, uint16_t port);
    Address(const sockaddr_any* addr, size_t addrlen);
    Address(const Address& addr) {
        *this = addr;
    }
    Address& operator=(const Address& addr);

    // Implicit conversion to sockaddr* and ngtcp2_addr& so that an Address can be passed wherever
    // one of those is expected.
    operator sockaddr*() { return a.addr; }
    operator const sockaddr*() const { return a.addr; }
    constexpr socklen_t sockaddr_size() const { return a.addrlen; }
    operator ngtcp2_addr&() { return a; }
    operator const ngtcp2_addr&() const { return a; }

    std::string to_string() const;
};

// Wraps an ngtcp2_path (which is basically just and address pair) with remote/local components.
// Implicitly convertable to a ngtcp2_path* so that this can be passed wherever a ngtcp2_path* is
// taken in the ngtcp2 API.
struct Path {
    Address local{}, remote{};
    ngtcp2_path path{
        {0, local, nullptr},
        {0, remote, nullptr}};

    Path() = default;
    Path(const Address& local, const Address& remote) : local{local}, remote{remote} {}
    Path(const Address& local, const sockaddr_any* remote_addr, size_t remote_len)
        : local{local}, remote{remote_addr, remote_len} {}
    Path(const Path& p) : local{p.local}, remote{p.remote} {}

    Path& operator=(const Path& p) {
        local = p.local;
        remote = p.remote;
        return *this;
    }

    // Equivalent to `&obj.path`, but slightly more convenient for passing into ngtcp2 functions
    // taking a ngtcp2_path pointer.
    operator ngtcp2_path*() { return &path; }
    operator const ngtcp2_path*() const { return &path; }

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& o, const Address& a);
std::ostream& operator<<(std::ostream& o, const Path& p);

}
