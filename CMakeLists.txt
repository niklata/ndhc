cmake_minimum_required(VERSION 3.3)
if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
  cmake_policy(VERSION 3.12)
endif()

project (ndhc DESCRIPTION "dhcp4 client" LANGUAGES C)

####################################

# Computes the realtionship between two version strings.  A version
# string is a number delineated by '.'s such as 1.3.2 and 0.99.9.1.
# You can feed version strings with different number of dot versions,
# and the shorter version number will be padded with zeros: 9.2 <
# 9.2.1 will actually compare 9.2.0 < 9.2.1.
#
# Input: a_in - value, not variable
#        b_in - value, not variable
#        result_out - variable with value:
#                         -1 : a_in <  b_in
#                          0 : a_in == b_in
#                          1 : a_in >  b_in
#
# Written by James Bigler.
MACRO(COMPARE_VERSION_STRINGS a_in b_in result_out)
  # Since SEPARATE_ARGUMENTS using ' ' as the separation token,
  # replace '.' with ' ' to allow easy tokenization of the string.
  STRING(REPLACE "." " " a ${a_in})
  STRING(REPLACE "." " " b ${b_in})
  SEPARATE_ARGUMENTS(a)
  SEPARATE_ARGUMENTS(b)

  # Check the size of each list to see if they are equal.
  LIST(LENGTH a a_length)
  LIST(LENGTH b b_length)

  # Pad the shorter list with zeros.

  # Note that range needs to be one less than the length as the for
  # loop is inclusive (silly CMake).
  IF(a_length LESS b_length)
    # a is shorter
    SET(shorter a)
    MATH(EXPR range "${b_length} - 1")
    MATH(EXPR pad_range "${b_length} - ${a_length} - 1")
  ELSE(a_length LESS b_length)
    # b is shorter
    SET(shorter b)
    MATH(EXPR range "${a_length} - 1")
    MATH(EXPR pad_range "${a_length} - ${b_length} - 1")
  ENDIF(a_length LESS b_length)

  # PAD out if we need to
  IF(NOT pad_range LESS 0)
    FOREACH(pad RANGE ${pad_range})
      # Since shorter is an alias for b, we need to get to it by by dereferencing shorter.
      LIST(APPEND ${shorter} 0)
    ENDFOREACH(pad RANGE ${pad_range})
  ENDIF(NOT pad_range LESS 0)

  SET(result 0)
  FOREACH(index RANGE ${range})
    IF(result EQUAL 0)
      # Only continue to compare things as long as they are equal
      LIST(GET a ${index} a_version)
      LIST(GET b ${index} b_version)
      # LESS
      IF(a_version LESS b_version)
        SET(result -1)
      ENDIF(a_version LESS b_version)
      # GREATER
      IF(a_version GREATER b_version)
        SET(result 1)
      ENDIF(a_version GREATER b_version)
    ENDIF(result EQUAL 0)
  ENDFOREACH(index)

  # Copy out the return result
  SET(${result_out} ${result})
ENDMACRO(COMPARE_VERSION_STRINGS)

####################################

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -fno-strict-overflow -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -DNK_USE_CAPABILITY -Wno-discarded-qualifiers")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -fno-strict-overflow -fno-rtti -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -DNK_USE_CAPABILITY")

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()

if (NOT (${OSNAME} STREQUAL "Linux"))
  message("ndhc requires Linux.  Patches are welcome.  Consult README.")
  return()
endif()

if (${OSNAME} STREQUAL "Linux")
  execute_process(
    COMMAND uname -r
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE LINUX_VERSION
    )
  COMPARE_VERSION_STRINGS(${LINUX_VERSION} "3.5" LINUX_HAS_NO_NEW_PRIVS)
  if (NOT ${LINUX_HAS_NO_NEW_PRIVS} LESS 0)
    message("ncmlib: Enabling use of prctl SET_NO_NEW_PRIVS.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNK_USE_NO_NEW_PRIVS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNK_USE_NO_NEW_PRIVS")
  else()
    message("ncmlib: prctl SET_NO_NEW_PRIVS not available.")
  endif()
  COMPARE_VERSION_STRINGS(${LINUX_VERSION} "3.17" LINUX_HAS_GETRANDOM_SYSCALL)
  if (NOT ${LINUX_HAS_GETRANDOM_SYSCALL} LESS 0)
    message("ncmlib: Enabling use of getrandom syscall.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNK_USE_GETRANDOM_SYSCALL")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNK_USE_GETRANDOM_SYSCALL")
  else()
    message("ncmlib: getrandom syscall not available.")
  endif()
endif()

if (NOT CMAKE_CROSSCOMPILING)
  set(GLIBC_DETECT_TEST_C
    "
    #include <stdio.h>
    int main(int argc, char *argv[]) {
    printf(\"%d.%d\", __GLIBC__, __GLIBC_MINOR__);
    return 0;
    }
    ")
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/detect/glibc.c "${GLIBC_DETECT_TEST_C}\n")
  try_run(GLIBC_DETECTION GLIBC_COMPILE
    ${CMAKE_CURRENT_BINARY_DIR}/detect ${CMAKE_CURRENT_BINARY_DIR}/detect/glibc.c
    RUN_OUTPUT_VARIABLE GLIBC_VERSION)
  if (GLIBC_VERSION AND GLIBC_COMPILE)
    message("glibc version detected as ${GLIBC_VERSION}")
    COMPARE_VERSION_STRINGS(${GLIBC_VERSION} "2.17" GLIBC_MUST_LINK_RT)
    if (${GLIBC_MUST_LINK_RT} LESS 0)
      message("glibc <2.17 detected; linking against librt.")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lrt")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lrt")
    endif()
  else()
    message("Could not detect glibc version.")
  endif()
endif()

if ("$ENV{CROSSCOMPILE_MACHINENAME}" STREQUAL "")
  execute_process(
    COMMAND uname -m
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE MACHINENAME
    )
else()
  message("skipped machine detection; MACHINENAME is '$ENV{CROSSCOMPILE_MACHINENAME}'")
  set(MACHINENAME $ENV{CROSSCOMPILE_MACHINENAME})
endif()

add_executable(ndhc "")

set(RAGEL_IFCHD_PARSE ${CMAKE_CURRENT_BINARY_DIR}/ifchd-parse.c)
set(RAGEL_CFG_PARSE ${CMAKE_CURRENT_BINARY_DIR}/cfg.c)

find_program(RAGEL ragel)

set(RAGEL_PRINT_COMMENT "Compiling Ragel state machine: FILE")
file(GLOB_RECURSE RAGEL_FILES
  "src/ifchd-parse.rl"
  "src/cfg.rl"
  )
foreach(RAGEL_FILE ${RAGEL_FILES})
  string(REGEX REPLACE "^[^/]*[/]" "" RAGEL_FILE_BASE ${RAGEL_FILE})
  string(REGEX REPLACE ${RAGEL_FILE_BASE} "" RAGEL_FILE_PATH ${RAGEL_FILE})
  string(REGEX REPLACE "[.]rl$" ".c" RAGEL_FILE_C ${RAGEL_FILE_BASE})
  string(REGEX REPLACE "FILE$" ${RAGEL_FILE_BASE} RAGEL_COMMENT ${RAGEL_PRINT_COMMENT})
  set(RAGEL_FILE_C_OUT ${CMAKE_CURRENT_BINARY_DIR}/${RAGEL_FILE_C})
  list(APPEND RAGEL_C_FILES ${RAGEL_FILE_C_OUT})
  add_custom_command(
    OUTPUT ${RAGEL_FILE_C_OUT}
    COMMAND ${RAGEL} -T0 ${RAGEL_ERRFMT_ARG} -o ${RAGEL_FILE_C_OUT} ${RAGEL_FILE_BASE}
    MAIN_DEPENDENCY ${RAGEL_FILE}
    WORKING_DIRECTORY ${RAGEL_FILE_PATH}
    COMMENT ${RAGEL_COMMENT}
    VERBATIM
    )
  set_property(SOURCE ${RAGEL_FILE_C_OUT} APPEND PROPERTY GENERATED TRUE)
  if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set_property(SOURCE ${RAGEL_FILE_C_OUT} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-unused-const-variable")
  endif()
  set_source_files_properties(${RAGEL_FILE_C_OUT} PROPERTIES GENERATED true)
  target_sources(ndhc PRIVATE ${RAGEL_FILE_C_OUT})
endforeach(RAGEL_FILE)
add_custom_target(ndhc_ragel DEPENDS ${RAGEL_C_FILES})
add_dependencies(ndhc ndhc_ragel)

target_sources(ndhc PRIVATE
  "src/lib/io.c"
  "src/lib/log.c"
  "src/lib/hwrng.c"
  "src/lib/random.c"
  "src/lib/privs.c"
  ${RAGEL_C_FILES}
  "src/arp.c"
  "src/ifchd.c"
  "src/netlink.c"
  "src/sockd.c"
  "src/dhcp.c"
  "src/ifset.c"
  "src/nl.c"
  "src/state.c"
  "src/duiaid.c"
  "src/leasefile.c"
  "src/options.c"
  "src/sys.c"
  "src/ifchange.c"
  "src/ndhc.c"
  "src/rfkill.c"
)
target_include_directories(ndhc PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  )
