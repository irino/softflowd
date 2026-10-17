sbin_PROGRAMS = softflowd softflowctl
COMMON = common.h convtime.h treetype.h compat/bsd/sys-tree.h\
  convtime.c compat/bsd/strlcpy.c compat/bsd/strlcat.c compat/bsd/closefrom.c\
  daemon.c
if COMPAT_EXPORT_IS_STATIC_SEPARATE
  STATIC_SEPARATE_SOURCES = compat/netflow9.c compat/netflow1.c
endif
if COMPAT_EXPORT_IS_ENABLED
  STATIC_SOURCES = compat/ipfix.c compat/netflow5.c
endif
if ENABLE_NTOPNG
  NTOPNG_SOURCES = ntopng.c
endif
if ENABLE_NTOPNG_JSON
  NTOPNG_JSON_SOURCES = compat/ntopng-json.c
endif
softflowd_SOURCES = freelist.h log.h softflowd.h netflow.h ipfix.h psamp.h\
	freelist.c softflowd.c log.c export.c $(STATIC_SOURCES) psamp.c\
  $(COMMON)
EXTRA_softflowd_SOURCES = $(STATIC_SEPARATE_SOURCES) $(NTOPNG_SOURCES) $(NTOPNG_JSON_SOURCES)
softflowd_LDADD = $(STATIC_SEPARATE_OBJECTS) $(NTOPNG) $(NTOPNG_JSON) $(XXHASH_LIBS)
softflowd_DEPENDENCIES = $(STATIC_SEPARATE_OBJECTS) $(NTOPNG) $(NTOPNG_JSON)
softflowctl_SOURCES = softflowctl.c $(COMMON)
dist_man_MANS = softflowd.8 softflowctl.8
EXTRA_DIST = softflowd.spec softflowd.init softflowd.sysconfig README.md
