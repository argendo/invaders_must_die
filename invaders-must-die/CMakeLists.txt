cmake_minimum_required(VERSION 3.0.0)
project(invaders-must-die VERSION 0.1.0 LANGUAGES C CXX)

include(common.cmake)
include(CTest)
enable_testing()

find_package (Threads)

add_subdirectory(src/log.c)
add_subdirectory(src/detector)
add_subdirectory(src/console_sender)
add_subdirectory(src/grpc_sender)

add_executable(invaders-must-die main.cpp)

target_link_libraries(invaders-must-die pcap logc systemd console_sender grpc_sender detector ${CMAKE_THREAD_LIBS_INIT} hw_grpc_proto
absl::flags
absl::flags_parse
${_REFLECTION}
${_GRPC_GRPCPP}
${_PROTOBUF_LIBPROTOBUF})
target_include_directories(${PROJECT_NAME} PUBLIC 
$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
