project (ifchd)

cmake_minimum_required (VERSION 2.6)

set(RAGEL_IFCHD_PARSE ${CMAKE_CURRENT_BINARY_DIR}/ifchd-parse.c)

find_program(RAGEL ragel)
add_custom_command(
  OUTPUT ${RAGEL_IFCHD_PARSE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_IFCHD_PARSE} ifchd-parse.rl
  DEPENDS ifchd-parse.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: ifchd-parse.rl"
  VERBATIM
  )

file(GLOB IFCHD_SRCS "*.c")

add_executable(ifchd ${RAGEL_IFCHD_PARSE} ${IFCHD_SRCS})
target_link_libraries(ifchd ncmlib)
