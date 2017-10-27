
AC_PREREQ(2.6)
AC_INIT([codecrypt], [1.7.6])
AC_CONFIG_AUX_DIR(.) # because of libtoolize
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE()
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

CFLAGS="$CFLAGS"
CXXFLAGS="$CXXFLAGS"
LDFLAGS="$LDFLAGS"

LT_INIT

AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL

#check for compilable GMP presence
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([Codecrypt requires gmp.h]))
AC_CHECK_LIB(gmp, __gmpz_init, , AC_MSG_ERROR([Codecrypt requires libgmp]))

#check for FFTW library presence
AC_CHECK_HEADERS([fftw3.h], , AC_MSG_ERROR([Codecrypt requires fftw3.h]))
AC_CHECK_LIB(fftw3, fftw_plan_dft_1d, , AC_MSG_ERROR([Codecrypt requires libfftw3]))

#check whether to build with crypto++
AC_ARG_WITH([cryptopp],
	AC_HELP_STRING([--with-cryptopp],[Build algorithms that need Crypto++ support]),
	[WITH_CRYPTOPP=$withval],
	[WITH_CRYPTOPP=yes])

#and check crypto++
if test "$WITH_CRYPTOPP" = "yes"; then
	
	PKG_PROG_PKG_CONFIG([0.25])

	PKG_CHECK_MODULES([CRYPTOPP],[libcrypto++])

	#crypto++ headers are either in include/crypto++ or include/cryptopp,
	#the information is otherwise unavailable from standard configuration
	#means. Please report/add more tests if you encounter distros that
	#place them elsewhere.
	AC_LANG_PUSH([C++])
	AC_CHECK_HEADER([crypto++/config.h],
		AC_DEFINE([CRYPTOPP_DIR_PLUS], [1]),
		AC_DEFINE([CRYPTOPP_DIR_PLUS], [0])
	)
	AC_LANG_POP([C++])

	AC_DEFINE([HAVE_CRYPTOPP], [1])
else
	AC_DEFINE([HAVE_CRYPTOPP], [0])
fi

#check for readpassphrase. If none is found, we use getpass (with a warning)
AC_CHECK_HEADER([readpassphrase.h],
	[READPASSPHRASE=native],
	AC_CHECK_HEADER([bsd/readpassphrase.h],
		[READPASSPHRASE=bsd], ))

if test "$READPASSPHRASE" = "native"; then
	AC_DEFINE([HAVE_READPASSPHRASE], [1])
fi
if test "$READPASSPHRASE" = "bsd"; then
	AC_DEFINE([HAVE_BSDREADPASSPHRASE], [1])
	AC_CHECK_LIB([bsd], [readpassphrase],
		[LIBS="-lbsd $LIBS"], #is there a better version of this?
		AC_MSG_ERROR([library for bsd/readpassphrase.h not found]))
fi

#check for standard functions
AC_CHECK_FUNCS([memset mkdir], , AC_MSG_ERROR([Required function missing]))

#unixy headers
AC_CHECK_HEADERS([fcntl.h inttypes.h stddef.h stdlib.h string.h sys/file.h unistd.h], , AC_MSG_ERROR([Required header file missing]))

#other used stuff
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
