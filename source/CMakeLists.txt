cmake_minimum_required(VERSION 3.0.0)
project(invaders_must_die VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_subdirectory(log.c)
add_executable(invaders_must_die main.cpp)
target_link_libraries(invaders_must_die pcap logc systemd)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
