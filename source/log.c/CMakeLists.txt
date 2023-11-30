add_library(logc "")

target_sources(logc
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/log.c
  PUBLIC ${CMAKE_CURRENT_LIST_DIR}/log.h)

target_include_directories(logc PUBLIC ${CMAKE_CURRENT_LIST_DIR})