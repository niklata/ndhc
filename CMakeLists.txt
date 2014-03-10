project (ndhcp)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -pedantic -Wall -Wno-format-extra-args -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -lrt -lcap -D_GNU_SOURCE -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -pedantic -Wall -Wno-format-extra-args -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -lrt -lcap -D_GNU_SOURCE -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

add_subdirectory(ndhc)
