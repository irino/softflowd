sbin_PROGRAMS = softflowd softflowctl
COMMON = common.h convtime.h treetype.h sys-tree.h\
  convtime.c strlcpy.c strlcat.c closefrom.c daemon.c
if UNIFIED_EXPORT_TYPE_NONE
  LEGACY_SOURCES = netflow9.c netflow1.c
endif
if UNIFIED_EXPORT_TYPE_FULL
  NETFLOW5_SOURCE =
else
  NETFLOW5_SOURCE = netflow5.c
endif
if ENABLE_NTOPNG
  NTOPNG_SOURCES = ntopng.c
endif
softflowd_SOURCES = freelist.h log.h softflowd.h netflow5.h netflow9.h ipfix.h psamp.h\
	freelist.c softflowd.c log.c $(NETFLOW5_SOURCE) ipfix.c psamp.c\
  $(COMMON)
EXTRA_softflowd_SOURCES = $(LEGACY_SOURCES) $(NTOPNG_SOURCES)
softflowd_LDADD = $(LEGACY) $(NTOPNG)
softflowd_DEPENDENCIES = $(LEGACY) $(NTOPNG)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
EXTRA_DIST = softflowd.spec softflowd.init softflowd.sysconfig
