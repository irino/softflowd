bin_PROGRAMS = softflowd softflowctl
COMMON = common.h convtime.h treetype.h sys-tree.h\
  convtime.c strlcpy.c strlcat.c closefrom.c daemon.c
if ENABLE_LEGACY
  LEGACY_SOURCES = netflow9.c netflow1.c
endif
if ENABLE_NTOPNG
  NTOPNG_SOURCES = ntopng.c
endif
softflowd_SOURCES = freelist.h log.h softflowd.h netflow9.h ipfix.h psamp.h\
	freelist.c softflowd.c log.c netflow5.c ipfix.c psamp.c\
  $(COMMON)
EXTRA_softflowd_SOURCES = $(LEGACY_SOURCES) $(NTOPNG_SOURCES)
softflowd_LDADD = $(LEGACY) $(NTOPNG)
softflowd_DEPENDENCIES = $(LEGACY) $(NTOPNG)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
