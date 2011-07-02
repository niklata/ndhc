project (ndhcp)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -pedantic -Wall -lcap -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -pedantic -Wall -lcap -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)
include_directories("${PROJECT_SOURCE_DIR}/libmnl")
add_subdirectory(libmnl)

add_subdirectory(ifchd)
add_subdirectory(ndhc)
