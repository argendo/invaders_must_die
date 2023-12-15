cmake_minimum_required(VERSION 3.8)

project(grpc_sender C CXX)
#include(../../common.cmake)
# Proto file
get_filename_component(hw_proto "proto/alert.proto" ABSOLUTE)
get_filename_component(hw_proto_path "${hw_proto}" PATH)

# Generated sources
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/alert.pb.cc")
set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/alert.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/alert.grpc.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/alert.grpc.pb.h")
add_custom_command(
      OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}" "${hw_grpc_srcs}" "${hw_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${hw_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
      DEPENDS "${hw_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# hw_grpc_proto
add_library(hw_grpc_proto
  ${hw_grpc_srcs}
  ${hw_grpc_hdrs}
  ${hw_proto_srcs}
  ${hw_proto_hdrs})

target_link_libraries(hw_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

# Targets greeter_[async_](client|server)
foreach(_target
  grpc_sender)
  add_library(${_target} "${_target}.cc")
  target_link_libraries(${_target}
    hw_grpc_proto
    detector
    absl::flags
    absl::flags_parse
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})
endforeach()

# target_link_libraries(grpc_sender detector)
target_include_directories(grpc_sender PUBLIC ${CMAKE_CURRENT_LIST_DIR} ../detector/)