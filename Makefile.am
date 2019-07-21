bin_PROGRAMS = softflowd softflowctl
COMMON = common.h convtime.h treetype.h sys-tree.h\
  convtime.c strlcpy.c strlcat.c closefrom.c daemon.c
softflowd_SOURCES = freelist.h log.h softflowd.h netflow9.h ipfix.h psamp.h\
	freelist.c softflowd.c log.c netflow5.c ipfix.c psamp.c\
  $(COMMON)
EXTRA_softflowd_SOURCES = netflow9.c netflow1.c
softflowd_LDADD = $(LEGACY)
softflowd_DEPENDENCIES = $(LEGACY)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
