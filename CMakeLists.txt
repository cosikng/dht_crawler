cmake_minimum_required(VERSION 3.16)

# Before project(): a toolchain (e.g. vcpkg) defines its find_package()
# wrapper while project() loads it, and functions keep the policies in effect
# at definition time. CMAKE_POLICY_DEFAULT covers nested package configs
# (libtorrent's looks up Boost).
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
    set(CMAKE_POLICY_DEFAULT_CMP0167 OLD)
endif()

project(dht_crawler LANGUAGES CXX)

option(DHT_CRAWLER_BUILD_TESTS "Build the unit and integration tests" ON)
option(DHT_CRAWLER_WERROR "Treat compiler warnings as errors" OFF)
option(DHT_CRAWLER_BUILD_BENCHMARKS "Build the DHT ingest benchmark" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
# 2.0.14 fixes a null dereference when a v1-only magnet's peer claims v2 support.
# The same fix requires 2.1.1 on the 2.1 branch; reject 2.1.0 below.
# https://github.com/arvidn/libtorrent/issues/8692
find_package(LibtorrentRasterbar 2.0.14 CONFIG QUIET)

if(TARGET SQLite3::SQLite3)
    set(SQLITE_TARGET SQLite3::SQLite3)
else()
    set(SQLITE_TARGET SQLite::SQLite3)
endif()

if(LibtorrentRasterbar_FOUND)
    set(LIBTORRENT_TARGET LibtorrentRasterbar::torrent-rasterbar)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(
        LibtorrentRasterbar
        REQUIRED
        IMPORTED_TARGET
        "libtorrent-rasterbar>=2.0.14"
    )
    set(LIBTORRENT_TARGET PkgConfig::LibtorrentRasterbar)
endif()

if(LibtorrentRasterbar_VERSION VERSION_GREATER_EQUAL "2.1.0"
    AND LibtorrentRasterbar_VERSION VERSION_LESS "2.1.1")
    message(FATAL_ERROR
        "libtorrent 2.1.0 is affected by issue #8692; use 2.0.14+ in the 2.0 series or 2.1.1+."
    )
endif()

# Portable runtime: sockets, signals, files, console output, logging.
add_library(crawler_platform STATIC
    platform.cpp
    simple_network.cpp
    logger.cpp
)
target_compile_features(crawler_platform PUBLIC cxx_std_17)
target_include_directories(crawler_platform PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(crawler_platform PUBLIC Threads::Threads)
if(WIN32)
    target_compile_definitions(crawler_platform PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
    # Winsock, and CommandLineToArgvW for the UTF-8 command line.
    target_link_libraries(crawler_platform PUBLIC ws2_32 shell32)
endif()

add_library(tracker_protocol STATIC tracker_protocol.cpp)
target_link_libraries(tracker_protocol PUBLIC crawler_platform)

# File index API (file_index.hpp): standalone, libtorrent-free, for the
# crawler, the dht_files tool and downstream applications.
add_library(file_index STATIC file_index.cpp)
target_link_libraries(file_index PUBLIC crawler_platform ${SQLITE_TARGET})

add_library(crawler_core STATIC
    hash_registry.cpp
    crawler_storage.cpp
)
target_link_libraries(crawler_core PUBLIC crawler_platform file_index ${SQLITE_TARGET})

add_executable(dht_db dht_db.cpp torrent_file_list.cpp)
target_link_libraries(dht_db PRIVATE crawler_core ${LIBTORRENT_TARGET})

add_executable(dht_files dht_files.cpp)
target_link_libraries(dht_files PRIVATE file_index)

add_executable(tracker_server tracker_server.cpp)
target_link_libraries(tracker_server PRIVATE tracker_protocol)

set(DHT_CRAWLER_TARGETS crawler_platform tracker_protocol file_index crawler_core dht_db dht_files tracker_server)

if(DHT_CRAWLER_BUILD_TESTS)
    enable_testing()

    add_executable(unit_tests tests/unit_tests.cpp)
    target_link_libraries(unit_tests PRIVATE crawler_core tracker_protocol)
    list(APPEND DHT_CRAWLER_TARGETS unit_tests)
    add_test(NAME unit_tests COMMAND unit_tests)
    set_tests_properties(unit_tests PROPERTIES TIMEOUT 300)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME integration_tests
            COMMAND
                ${Python3_EXECUTABLE} -I
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.py"
                --tracker "$<TARGET_FILE:tracker_server>"
                --crawler "$<TARGET_FILE:dht_db>"
                --files-tool "$<TARGET_FILE:dht_files>"
        )
        set_tests_properties(integration_tests PROPERTIES TIMEOUT 900)
    else()
        message(STATUS "Python 3 not found: integration_tests will not be registered")
    endif()
endif()

# CPU cost of DHT ingest per announce-capture strategy; run tests/dht_ingest_bench.py.
if(DHT_CRAWLER_BUILD_BENCHMARKS)
    add_executable(dht_ingest_bench tests/dht_ingest_bench.cpp)
    target_link_libraries(dht_ingest_bench PRIVATE ${LIBTORRENT_TARGET} Threads::Threads)
    list(APPEND DHT_CRAWLER_TARGETS dht_ingest_bench)
endif()

foreach(target IN LISTS DHT_CRAWLER_TARGETS)
    target_compile_options(
        ${target}
        PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>
            $<$<AND:$<BOOL:${DHT_CRAWLER_WERROR}>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>>:-Werror>
            # /utf-8: the sources and their (Chinese) log strings are UTF-8.
            $<$<CXX_COMPILER_ID:MSVC>:/W4;/permissive-;/utf-8>
            $<$<AND:$<BOOL:${DHT_CRAWLER_WERROR}>,$<CXX_COMPILER_ID:MSVC>>:/WX>
    )
endforeach()
