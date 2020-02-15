AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES =
include Makefile.clean.inc

EXTRA_DIST = \
	.gitignore \
	shadow/date \
	shadow/random \
	$(NULL)

bin_PROGRAMS = \
	fuse-exec \
	$(NULL)

dist_doc_DATA = \
	README.md \
	$(NULL)

fuse_exec_SOURCES = \
	fuse-exec.c \
	$(NULL)
fuse_exec_CFLAGS = \
	$(AM_CFLAGS) \
	$(FUSE_CFLAGS) \
	$(NULL)
fuse_exec_LDADD = \
	$(FUSE_LIBS) \
	$(NULL)
