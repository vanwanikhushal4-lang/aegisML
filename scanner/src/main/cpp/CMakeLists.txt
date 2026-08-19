cmake_minimum_required(VERSION 3.22.1)

project("aegis-scanner")

add_library(
        aegis-scanner
        SHARED
        hash_engine.cpp
        sig_matcher.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        aegis-scanner
        ${log-lib}
)
