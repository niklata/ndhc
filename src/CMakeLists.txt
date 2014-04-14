project (ndhc)

cmake_minimum_required (VERSION 2.6)

include_directories("${PROJECT_SOURCE_DIR}")

set(RAGEL_IFCHD_PARSE ${CMAKE_CURRENT_BINARY_DIR}/ifchd-parse.c)
set(RAGEL_CFG_PARSE ${CMAKE_CURRENT_BINARY_DIR}/cfg.c)

find_program(RAGEL ragel)
add_custom_command(
  OUTPUT ${RAGEL_IFCHD_PARSE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_IFCHD_PARSE} ifchd-parse.rl
  DEPENDS ifchd-parse.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: ifchd-parse.rl"
  VERBATIM
  )
add_custom_command(
  OUTPUT ${RAGEL_CFG_PARSE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_CFG_PARSE} cfg.rl
  DEPENDS cfg.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: cfg.rl"
  VERBATIM
  )

file(GLOB NDHC_SRCS "*.c")

add_executable(ndhc ${RAGEL_CFG_PARSE} ${RAGEL_IFCHD_PARSE} ${NDHC_SRCS})
target_link_libraries(ndhc ncmlib)
