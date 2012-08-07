AC_PREREQ(2.60)
AC_INIT([wdns], [0.4])
AC_CONFIG_SRCDIR([wdns/wdns.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

AC_PROG_SED
AC_PROG_MKDIR_P

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

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

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
])
