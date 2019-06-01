bin_PROGRAMS = softflowd softflowctl
COMMON = convtime.h  convtime.c strlcpy.c strlcat.c closefrom.c daemon.c
softflowd_SOURCES = common.h  freelist.h  log.h  softflowd.h sys-tree.h  treetype.h\
	freelist.c softflowd.c log.c netflow1.c netflow5.c netflow9.c ipfix.c $(COMMON)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
