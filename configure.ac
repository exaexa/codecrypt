AC_PREREQ([2.69])
AC_INIT([codecrypt], [1.8])
AC_CONFIG_AUX_DIR([build-aux]) dnl because of libtoolize
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE()
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT
AC_PROG_CXX

dnl check for compilable GMP presence
AC_CHECK_HEADERS([gmp.h], [], [AC_MSG_ERROR([Codecrypt requires gmp.h])])
AC_SEARCH_LIBS([__gmpz_init], [gmp], [], [AC_MSG_ERROR([Codecrypt requires libgmp])])

dnl check for FFTW library presence
PKG_CHECK_MODULES([FFTW3], [fftw3])

dnl check whether to build with crypto++
AC_ARG_WITH([cryptopp],
    [AS_HELP_STRING([--with-cryptopp], [Build algorithms that need Crypto++ support])])

dnl and check crypto++
AS_IF([test "x$with_cryptopp" != "xno"], [
    PKG_PROG_PKG_CONFIG([0.25])

    PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++], [], [
        AC_MSG_CHECKING([for libcrypto++ using known flags])
        AC_LANG_PUSH([C++])
        saved_LIBS="$LIBS"
        LIBS+=" -lcrypto++"
        AC_LINK_IFELSE([
            AC_LANG_PROGRAM([#include <crypto++/cryptlib.h>], [CryptoPP::NullRNG])], [
                CRYPTOPP_LIBS="-lcrypto++"
                AC_MSG_RESULT([${CRYPTOPP_LIBS}])
            ], [
                AC_MSG_ERROR([Cannot find crypto++])
            ])
        LIBS="$saved_LIBS"
        AC_LANG_POP([C++])
    ])

    AC_DEFINE([HAVE_CRYPTOPP], [1], [Enable support for crypto++ routines])
], [
    AC_DEFINE([HAVE_CRYPTOPP], [0], [Enable support for crypto++ routines])
])

dnl check for readpassphrase. If none is found, we use getpass (with a warning)
AC_CHECK_HEADER([readpassphrase.h],
    [READPASSPHRASE=native],
    AC_CHECK_HEADER([bsd/readpassphrase.h],
        [READPASSPHRASE=bsd], []))

AS_IF([test "x$READPASSPHRASE" = "xnative"],[
    AC_DEFINE([HAVE_READPASSPHRASE], [1], [Enable readpassphrase])])

AS_IF([test "x$READPASSPHRASE" = "xbsd"],[
    AC_DEFINE([HAVE_BSDREADPASSPHRASE], [1], [Enable bsdreadpassphrase])
    AC_SEARCH_LIBS([readpassphrase], [bsd], [], [AC_MSG_ERROR([library for bsd/readpassphrase.h not found])])])

dnl check for standard functions
AC_CHECK_FUNCS([memset mkdir], [], [AC_MSG_ERROR([Required function missing])])

dnl POSIX headers
AC_CHECK_HEADERS([fcntl.h inttypes.h stddef.h stdlib.h string.h sys/file.h unistd.h], [], [AC_MSG_ERROR([Required header file missing])])

dnl other used stuff
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
