project(console_sender VERSION 0.1.0 LANGUAGES C CXX)

add_library(console_sender "")

target_sources(console_sender
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/console_sender.cpp
  PUBLIC ${CMAKE_CURRENT_LIST_DIR}/console_sender.hpp)

target_link_libraries(console_sender yara detector)
target_include_directories(console_sender PUBLIC ${CMAKE_CURRENT_LIST_DIR} ../detector/)