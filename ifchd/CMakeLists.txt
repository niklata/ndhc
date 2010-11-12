project (ifchd)

cmake_minimum_required (VERSION 2.6)

set(IFCHD_SRCS
  ifchd.c
  linux.c
  )

add_executable(ifchd ${IFCHD_SRCS})
target_link_libraries(ifchd ncmlib)
