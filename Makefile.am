sbin_PROGRAMS = softflowd softflowctl
COMMON = common.h convtime.h treetype.h compat/sys-tree.h\
  convtime.c compat/strlcpy.c compat/strlcat.c compat/closefrom.c daemon.c
if EXPORT_MERGE_IS_NONE
  LEGACY_SOURCES = compat/netflow9.c compat/netflow1.c
endif
if EXPORT_MERGE_IS_ALL
  NETFLOW5_SOURCE =
else
  NETFLOW5_SOURCE = compat/netflow5.c
endif
if ENABLE_NTOPNG
  NTOPNG_SOURCES = ntopng.c
endif
softflowd_SOURCES = freelist.h log.h softflowd.h netflow.h ipfix.h psamp.h\
	freelist.c softflowd.c log.c $(NETFLOW5_SOURCE) ipfix.c psamp.c\
  $(COMMON)
EXTRA_softflowd_SOURCES = $(LEGACY_SOURCES) $(NTOPNG_SOURCES)
softflowd_LDADD = $(LEGACY) $(NTOPNG)
softflowd_DEPENDENCIES = $(LEGACY) $(NTOPNG)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
EXTRA_DIST = softflowd.spec softflowd.init softflowd.sysconfig
