cmake_minimum_required(VERSION 3.0.2)
project(bcryptw)

#option(WITH_UNIT_TESTS "enable building unit test executable" OFF)
#option(WITH_BENCHMARK "enable building benchmark executable" OFF)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON)
set(CMAKE_BUILD_TYPE Release)

set(bcryptw_VERSION 0.1.0)

if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -O3")
endif()

add_subdirectory(src)
add_subdirectory(test)

if(WITH_UNIT_TESTS)
  enable_testing()
  add_subdirectory(vendor/headerize)
  add_subdirectory(test)
endif()

if(WITH_BENCHMARK)
  add_subdirectory(vendor/benchmark)
  add_subdirectory(benchmark)
endif()
