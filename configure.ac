
AC_PREREQ(2.6)
AC_INIT([codecrypt], [devel-1])
AC_CONFIG_AUX_DIR(.) # because of libtoolize

AM_INIT_AUTOMAKE()
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES])

LT_INIT

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL

#check for compilable GMP presence
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([Codecrypt requires gmp.h]))
AC_CHECK_LIB(gmp, __gmpz_init, , AC_MSG_ERROR([Codecrypt requires libgmp]))

#check for standard functions
AC_CHECK_FUNCS([memset mkdir], , AC_MSG_ERROR([Required function missing]))

#unixy headers
AC_CHECK_HEADERS([fcntl.h inttypes.h stddef.h stdlib.h string.h sys/file.h unistd.h], , AC_MSG_ERROR([Required header file missing]))

#other used stuff
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
