cmake_minimum_required(VERSION 3.16)

project(dht_crawler LANGUAGES CXX)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(LibtorrentRasterbar 2.0 CONFIG QUIET)

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
        "libtorrent-rasterbar>=2.0"
    )
    set(LIBTORRENT_TARGET PkgConfig::LibtorrentRasterbar)
endif()

add_library(simple_network STATIC simple_network.cpp)
target_compile_features(simple_network PUBLIC cxx_std_17)
target_include_directories(simple_network PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(simple_network PUBLIC Threads::Threads)

add_executable(dht_db dht_db.cpp)
target_compile_features(dht_db PRIVATE cxx_std_17)
target_link_libraries(
    dht_db
    PRIVATE
        simple_network
        ${LIBTORRENT_TARGET}
        ${SQLITE_TARGET}
        Threads::Threads
)

add_executable(tracker_server tracker_server.cpp)
target_compile_features(tracker_server PRIVATE cxx_std_17)
target_link_libraries(tracker_server PRIVATE simple_network Threads::Threads)

foreach(target simple_network dht_db tracker_server)
    target_compile_options(
        ${target}
        PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>
            $<$<CXX_COMPILER_ID:MSVC>:/W4>
    )
endforeach()
