project (ifchd)

cmake_minimum_required (VERSION 2.6)

set(IFCHD_SRCS
  ifchd.c
  linux.c
  strlist.c
  signals.c
  pidfile.c
  chroot.c
  nstrl.c
  log.c
  )

add_executable(ifchd ${IFCHD_SRCS})
#target_link_libraries(ifchd ncmlib)
