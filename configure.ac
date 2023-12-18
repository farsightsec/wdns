AC_PREREQ(2.64)

m4_define(wdns_major_version, 0)
m4_define(wdns_minor_version, 12)
m4_define(wdns_patchlevel_version, 0)
m4_define(wdns_version,
          wdns_major_version.wdns_minor_version.wdns_patchlevel_version)

AC_INIT([wdns],
        [wdns_version()],
        [https://github.com/farsightsec/wdns/issues],
        [wdns],
        [https://github.com/farsightsec/wdns])
AC_CONFIG_SRCDIR([wdns/wdns.h.in])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
CC=${CC-"gcc -std=c99 -D_GNU_SOURCE"}
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

WDNS_MAJOR_VERSION=wdns_major_version()
WDNS_MINOR_VERSION=wdns_minor_version()
WDNS_PATCHLEVEL_VERSION=wdns_patchlevel_version()
WDNS_VERSION=wdns_version()

AC_SUBST(WDNS_MAJOR_VERSION)
AC_SUBST(WDNS_MINOR_VERSION)
AC_SUBST(WDNS_PATCHLEVEL_VERSION)
AC_SUBST(WDNS_VERSION)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile wdns/libwdns.pc wdns/wdns.h])

PKG_PROG_PKG_CONFIG
if test -n "$PKG_CONFIG"; then
    # Horrible hack for systems where the pkg-config install directory is simply wrong!
    if $PKG_CONFIG --variable=pc_path pkg-config 2>/dev/null | grep -q /libdata/; then
        PKG_INSTALLDIR(['${prefix}/libdata/pkgconfig'])
    else
        PKG_INSTALLDIR
    fi
else
    AC_MSG_ERROR([pkg-config is required!])
fi

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CHECK_HEADERS([alloca.h])

AC_CHECK_HEADER([pcap.h])
AC_CHECK_LIB([pcap], [pcap_loop],
    [
        AC_DEFINE([HAVE_LIBPCAP], [1], [Define to 1 if libpcap works.])
        have_libpcap=true
    ],
    [
        have_libpcap=false
    ]
)
AM_CONDITIONAL([LIBPCAP], [test "$have_libpcap" = "true"])

gl_LD_VERSION_SCRIPT

AC_ARG_WITH(coverage,
[ --with-coverage[=PROGRAM] enable gtest and coverage target using the specified lcov], lcov="$withval", lcov="no")


USE_LCOV="no"
if test "$lcov" != "no"; then
	if test "$lcov" != "yes"; then
		LCOV=$lcov
	else
		AC_PATH_PROG([LCOV], [lcov])
	fi
	if test -x "${LCOV}"; then
		USE_LCOV="yes"
	else
		AC_MSG_ERROR([Cannot find lcov.])
	fi
	# is genhtml always in the same directory?
	GENHTML=`echo "$LCOV" | ${SED} s/lcov$/genhtml/`
	if test ! -x $GENHTML; then
		AC_MSG_ERROR([genhtml not found, needed for lcov])
	fi
	CFLAGS="$CFLAGS --coverage"
	LIBS=" $LIBS -lgcov"
	AC_SUBST(CPPFLAGS)
	AC_SUBST(LIBS)
	AC_SUBST(LCOV)
	AC_SUBST(GENHTML)
fi
AC_SUBST(USE_LCOV)

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        CC:                     ${CC}
        CFLAGS:                 ${CFLAGS}
        LDFLAGS:                ${LDFLAGS}
        LIBS:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
        pkgconfigdir:           ${pkgconfigdir}

        code coverage enabled:  ${USE_LCOV}
])
