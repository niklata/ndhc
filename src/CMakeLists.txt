project (ndhc DESCRIPTION "dhcp4 client" LANGUAGES C)

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

add_executable(ndhc ${RAGEL_CFG_PARSE} ${RAGEL_IFCHD_PARSE})
target_sources(ndhc PRIVATE
  "arp.c"
  "ifchd.c"
  "netlink.c"
  "sockd.c"
  "dhcp.c"
  "ifset.c"
  "nl.c"
  "state.c"
  "duiaid.c"
  "leasefile.c"
  "options.c"
  "sys.c"
  "ifchange.c"
  "ndhc.c"
  "rfkill.c"
)
target_include_directories(ndhc PRIVATE
  "${PROJECT_SOURCE_DIR}"
  "${PROJECT_SOURCE_DIR}/../ncmlib"
  )
target_link_libraries(ndhc PUBLIC ncmlib)
