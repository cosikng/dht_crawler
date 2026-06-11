cmake_minimum_required(VERSION 3.16)

project(dht_crawler LANGUAGES CXX)

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(LibtorrentRasterbar CONFIG REQUIRED)

add_executable(dht_db dht_db.cpp)

target_compile_features(dht_db PRIVATE cxx_std_17)
target_compile_options(dht_db PRIVATE -O3)

target_link_libraries(
    dht_db
    PRIVATE
        LibtorrentRasterbar::torrent-rasterbar
        SQLite::SQLite3
        Threads::Threads
)
