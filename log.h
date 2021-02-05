#pragma once

#include <cstdarg>
#include <type_traits>
#pragma once

// Temporary logging code to be replaced with lokinet logging

#include <iostream>
#include <oxenmq/hex.h>

#ifdef __cpp_lib_source_location
#include <source_location>
namespace slns = std;
#else
#include <experimental/source_location>
namespace slns = std::experimental;
#endif

namespace quic {

template <typename It>
std::string make_printable(It begin, It end) {
    static_assert(sizeof(*begin) == 1);
    std::string out;
    auto size = std::distance(begin, end);
    out.reserve(size + 10);
    out += "[" + std::to_string(size) + "]\"";
    for (; begin != end; begin++) {
        auto c = static_cast<uint8_t>(*begin);
        if (c == '\\' || c == '"') {
            out += '\\';
            out += c;
        } else if (c <= 0x1f || c >= 0x7f) {
            out += "\\x";
            out += oxenmq::to_hex(&c, &c+1);
        } else {
            out += c;
        }
    }
    out += '"';
    return out;
}
template <typename Container>
std::string make_printable(const Container &cont) {
    return make_printable(std::begin(cont), std::end(cont));
}

namespace detail {

template <typename T, typename... V>
constexpr bool is_same_any_v = (std::is_same_v<T, V> || ...);

template <typename T, typename... More>
void log_print_vals(T&& val, More&&... more) {
    using PlainT = std::remove_reference_t<T>;
    if constexpr (is_same_any_v<PlainT, char, unsigned char, signed char, uint8_t, std::byte>)
        std::cerr << +val; // Promote chars to int so that they get printed as numbers, not literal chars
    else
        std::cerr << val;
    if constexpr (sizeof...(More))
        log_print_vals(std::forward<More>(more)...);
}

template <typename... T>
void log_print(const slns::source_location& location, T&&... args) {
    std::cerr << '[' << location.file_name() << ':' << location.line() << ']';
    if constexpr (sizeof...(T)) {
        std::cerr << ": ";
        detail::log_print_vals(std::forward<T>(args)...);
    }
    std::cerr << '\n';
}

} // namespace detail

#ifndef NDEBUG
template <typename... T>
struct Debug {
    Debug(T&&... args, const slns::source_location& location = slns::source_location::current()) {
        std::cerr << "DBG";
        detail::log_print(location, std::forward<T>(args)...);
    }
};
template <typename... T>
Debug(T&&...) -> Debug<T...>;
#else
template <typename... T> void Debug(T&&...) {}
#endif

template <typename... T>
struct Warn {
    Warn(T&&... args, const slns::source_location& location = slns::source_location::current()) {
        std::cerr << "WRN";
        detail::log_print(location, std::forward<T>(args)...);
    }
};
template <typename... T>
Warn(T&&...) -> Warn<T...>;

}
