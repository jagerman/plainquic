cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

project(plainquic
    VERSION 0.0.1
    DESCRIPTION "QUIC test implementation"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(NGTCP2_DIR "${PROJECT_SOURCE_DIR}/../build" CACHE "PATH" "Path to built ngtpc2 build dir")

add_library(quictest
    address.cpp
    client.cpp
    connection.cpp
    endpoint.cpp
    log.cpp
    null-crypto.cpp
    server.cpp
    stream.cpp
    tunnel.cpp
    )

add_library(ngtcp2 STATIC IMPORTED GLOBAL)
set_target_properties(ngtcp2 PROPERTIES IMPORTED_LOCATION ${NGTCP2_DIR}/lib/libngtcp2.a)
target_include_directories(ngtcp2 INTERFACE ${NGTCP2_DIR}/lib/includes ${NGTCP2_DIR}/../lib/includes)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv>=1.18.0 IMPORTED_TARGET)
pkg_check_modules(OXENMQ REQUIRED liboxenmq>=1.2.3 IMPORTED_TARGET)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.17 IMPORTED_TARGET)

target_link_libraries(quictest PUBLIC ngtcp2 PkgConfig::LIBUV PkgConfig::OXENMQ PkgConfig::SODIUM)
target_include_directories(quictest PUBLIC uvw/src)

add_executable(tunnel-server tunnel-server.cpp)
add_executable(tunnel-client tunnel-client.cpp)

target_link_libraries(tunnel-server quictest)
target_link_libraries(tunnel-client quictest)
