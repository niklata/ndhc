set(NCMLIB_SRCS
  malloc.c
  chroot.c
  pidfile.c
  signals.c
  strlist.c
  strl.c
  log.c
  cap.c
  io.c
  )

add_library(ncmlib ${NCMLIB_SRCS})