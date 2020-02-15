AC_INIT([fuse-exec], [0.0.0])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC_STDC
PKG_PROG_PKG_CONFIG
AC_CANONICAL_HOST
AC_SYS_LARGEFILE

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

PKG_CHECK_MODULES(
	[FUSE],
	[fuse3x],
	[ac_av_fuse_version=31],
	[PKG_CHECK_MODULES(
		[FUSE],
		[fuse],
		[ac_av_fuse_version=26],
		[AC_MSG_ERROR([fuse is required])]
	)]
)

AC_DEFINE_UNQUOTED([FUSE_USE_VERSION], [${ac_av_fuse_version}], [FUSE version])

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_OUTPUT([
	Makefile
])
