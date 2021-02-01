#pragma once

#include <cstdarg>
#include <iostream>

#ifdef __cpp_lib_source_location
#include <source_location>
namespace slns = std;
#else
#include <experimental/source_location>
namespace slns = std::experimental;
#endif

namespace quic {

#ifndef NDEBUG
template <typename... T>
struct Debug {
    Debug(T&&... args, const slns::source_location& location = slns::source_location::current()) {
        std::cerr << "[" << location.file_name() << ":" << location.line() << "]: ";
        (std::cerr << ... << std::forward<T>(args)) << '\n';
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
        std::cerr << "[" << location.file_name() << ":" << location.line() << "]: ";
        (std::cerr << ... << std::forward<T>(args)) << '\n';
    }
};
template <typename... T>
Warn(T&&...) -> Warn<T...>;

}
