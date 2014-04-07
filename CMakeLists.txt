project (ndhc)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -D_GNU_SOURCE -DNK_USE_CAPABILITY")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -D_GNU_SOURCE -DNK_USE_CAPABILITY")

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

execute_process(
  COMMAND uname -m
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE MACHINENAME
  )

if (${MACHINENAME} STREQUAL "x86_64")
  message("Detected that the current host is x86_64.  Enabling seccomp-filter.")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_SECCOMP_FILTER")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DENABLE_SECCOMP_FILTER")
elseif ((${MACHINENAME} STREQUAL "i686") OR (${MACHINENAME} STREQUAL "i586") OR
        (${MACHINENAME} STREQUAL "i486") OR (${MACHINENAME} STREQUAL "i386"))
  message("Detected that the current host is x86.  Enabling seccomp-filter.")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_SECCOMP_FILTER")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DENABLE_SECCOMP_FILTER")
else()
  message("Host machine type does not support seccomp-filter.")
endif()

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

add_subdirectory(src)
