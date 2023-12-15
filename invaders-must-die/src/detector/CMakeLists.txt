project(detector VERSION 0.1.0 LANGUAGES C CXX)

add_library(detector "")

target_sources(detector
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/detector.cpp
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ISender.cpp
  PUBLIC ${CMAKE_CURRENT_LIST_DIR}/detector.hpp
  PUBLIC ${CMAKE_CURRENT_LIST_DIR}/ISender.hpp)

target_link_libraries(detector yara logc)
target_include_directories(detector PUBLIC ${CMAKE_CURRENT_LIST_DIR} ../log.c)