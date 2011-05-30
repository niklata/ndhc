project (ndhc)

cmake_minimum_required (VERSION 2.6)

file(GLOB NDHC_SRCS "*.c")

add_executable(ndhc ${NDHC_SRCS})
target_link_libraries(ndhc ncmlib)
