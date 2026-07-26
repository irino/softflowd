cmake_minimum_required(VERSION 3.16)
project(softflowd+ CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Following the practices described in the article
# ( https://mecanik.dev/ja/posts/c++-vs-rust-memory-safety-practical-examples-with-modern-c++/ ),
# warnings and sanitizers are enabled by default so undefined behavior is
# easy to catch during development.
add_compile_options(
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  -Wnon-virtual-dtor -Woverloaded-virtual -Wnull-dereference
)

option(SOFTFLOW_ENABLE_SANITIZERS "Enable AddressSanitizer/UndefinedBehaviorSanitizer" ON)
if(SOFTFLOW_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

find_library(PCAP_LIBRARY pcap REQUIRED)
find_package(Threads REQUIRED)

# src/softflowd.cpp mirrors the original softflowd.c: it contains the
# FlowTable / PacketParser / PcapHandle implementations *and* main(), all in
# one translation unit. netflow1.cpp / netflow5.cpp / netflow9.cpp /
# ipfix.cpp / psamp.cpp / daemon.cpp are kept as separate files mirroring
# the original project's own per-file boundaries (see README for the
# rationale). softflowctl.cpp is compiled separately below, since -- like
# the original -- it is its own standalone client program, not part of
# softflowd's own logic.
set(SOFTFLOW_LOGIC_SOURCES
  src/softflowd.cpp
  src/netflow1.cpp
  src/netflow5.cpp
  src/netflow9.cpp
  src/ipfix.cpp
  src/psamp.cpp
  src/daemon.cpp
)

# Compiled once, with SOFTFLOW_NO_MAIN (which compiles softflowd.cpp's
# main() out), as an object library that the test executables link
# against, since each test supplies its own main().
add_library(softflow_core OBJECT ${SOFTFLOW_LOGIC_SOURCES})
target_include_directories(softflow_core PUBLIC include)
target_link_libraries(softflow_core PUBLIC ${PCAP_LIBRARY})
target_compile_definitions(softflow_core PUBLIC SOFTFLOW_NO_MAIN)

# softflowctl.cpp likewise contains both shared control-protocol wire
# helpers (read_line/write_line/ControlClient, used by softflowd.cpp's
# control-socket server as well as by softflowctl itself) and its own
# main(), also guarded by SOFTFLOW_NO_MAIN. Compiled once, without main,
# as its own small object library so both softflowd+ and the test
# binaries can link the protocol helpers without duplicating them.
add_library(softflowctl_lib OBJECT src/softflowctl.cpp)
target_include_directories(softflowctl_lib PUBLIC include)
target_compile_definitions(softflowctl_lib PRIVATE SOFTFLOW_NO_MAIN)

# The softflowd+ daemon executable: SOFTFLOW_LOGIC_SOURCES compiled
# directly (with main() included, since SOFTFLOW_NO_MAIN is not defined
# for this target), linked against softflowctl_lib for the control-socket
# wire-protocol helpers.
add_executable(softflowd+ ${SOFTFLOW_LOGIC_SOURCES})
target_include_directories(softflowd+ PRIVATE include)
target_link_libraries(softflowd+ PRIVATE ${PCAP_LIBRARY} softflowctl_lib)

# The standalone softflowctl+ client tool (original: softflowctl.c):
# src/softflowctl.cpp compiled directly, with its own main() included.
add_executable(softflowctl+ src/softflowctl.cpp)
target_include_directories(softflowctl+ PRIVATE include)

enable_testing()

add_executable(test_flow_table tests/test_flow_table.cpp)
target_link_libraries(test_flow_table PRIVATE softflow_core)
add_test(NAME flow_table COMMAND test_flow_table)

add_executable(test_packet_parser tests/test_packet_parser.cpp)
target_link_libraries(test_packet_parser PRIVATE softflow_core)
add_test(NAME packet_parser COMMAND test_packet_parser)

add_executable(test_netflow1 tests/test_netflow1.cpp)
target_link_libraries(test_netflow1 PRIVATE softflow_core)
add_test(NAME netflow1 COMMAND test_netflow1)

add_executable(test_netflow5 tests/test_netflow5.cpp)
target_link_libraries(test_netflow5 PRIVATE softflow_core)
add_test(NAME netflow5 COMMAND test_netflow5)

add_executable(test_netflow9 tests/test_netflow9.cpp)
target_link_libraries(test_netflow9 PRIVATE softflow_core)
add_test(NAME netflow9 COMMAND test_netflow9)

add_executable(test_ipfix tests/test_ipfix.cpp)
target_link_libraries(test_ipfix PRIVATE softflow_core)
add_test(NAME ipfix COMMAND test_ipfix)

add_executable(test_psamp tests/test_psamp.cpp)
target_link_libraries(test_psamp PRIVATE softflow_core)
add_test(NAME psamp COMMAND test_psamp)

add_executable(test_daemon tests/test_daemon.cpp)
target_link_libraries(test_daemon PRIVATE softflow_core)
add_test(NAME daemon COMMAND test_daemon)

add_executable(test_softflowctl tests/test_softflowctl.cpp)
target_link_libraries(test_softflowctl PRIVATE softflowctl_lib Threads::Threads)
add_test(NAME softflowctl COMMAND test_softflowctl)
