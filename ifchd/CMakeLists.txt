project (ifchd)

cmake_minimum_required (VERSION 2.6)

file(GLOB IFCHD_SRCS "*.c")

add_executable(ifchd ${IFCHD_SRCS})
target_link_libraries(ifchd ncmlib)
