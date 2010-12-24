project (ndhc)

cmake_minimum_required (VERSION 2.6)

set(NDHC_SRCS
  sys.c
  options.c
  socket.c
  packet.c
  timeout.c
  script.c
  clientpacket.c
  arpping.c
  ndhc.c
  )

add_executable(ndhc ${NDHC_SRCS})
target_link_libraries(ndhc ncmlib)
