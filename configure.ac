#
#
# Created by Daniel Black <dragonheart@gentoo.org> for the l7-filter projects
#

AC_PREREQ(2.61)
AC_INIT(l7-filter-userspace, [0.8], [http://sourceforge.net/tracker/?group_id=80085])
AC_CONFIG_SRCDIR([l7-queue.h])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)

AC_PROG_CXX

PKG_CHECK_MODULES([NFNETLINK], [libnetfilter_conntrack libnetfilter_queue])
AC_CHECK_LIB(pthread, main)

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([regcomp strerror strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
