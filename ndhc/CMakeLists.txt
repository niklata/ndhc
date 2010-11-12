project (ndhc)

cmake_minimum_required (VERSION 2.6)

set(NDHC_SRCS
  nstrl.c
  log.c
  options.c
  socket.c
  packet.c
  rootcap.c
  script.c
  clientpacket.c
  dhcpc.c
  )

add_executable(ndhc ${NDHC_SRCS})
#target_link_libraries(ndhc ncmlib)
