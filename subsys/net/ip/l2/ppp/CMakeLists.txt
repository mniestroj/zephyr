zephyr_library_named(subsys__net__ip__l2__ppp)
zephyr_library_include_directories(. ../..)
zephyr_library_compile_definitions_ifdef(
  CONFIG_NEWLIB_LIBC __LINUX_ERRNO_EXTENSIONS__
  )

zephyr_library_sources(
  ipcp.c
  lcp.c
  options.c
  pap.c
  ppp.c
  )

zephyr_library_sources_ifdef(CONFIG_PPP_L2_SERIAL serial.c)
