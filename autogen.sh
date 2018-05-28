#!/bin/bash

# simple autogen script that generates basic layout for autotools.

NAME="ccr"

OUT=Makefile.am
touch NEWS AUTHORS ChangeLog
echo > $OUT

DISTDIRS=""

echo "AUTOMAKE_OPTIONS = subdir-objects" >>$OUT
echo "ACLOCAL_AMFLAGS = -I m4" >>$OUT
echo "dist_man_MANS = man/${NAME}.1" >>$OUT
echo "dist_noinst_SCRIPTS = autogen.sh" `for i in $DISTDIRS ; do find \$i -type f ; done | tr "\n" " " ` >>$OUT

echo "bin_PROGRAMS = ${NAME}" >>$OUT
echo "${NAME}_SOURCES = `( find src/ -type f -name \*.c ; find src/ -type f -name \*.cpp ) |tr \"\n\" \" \" ` " >>$OUT
echo "noinst_HEADERS = `find src/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT
echo "AM_CPPFLAGS = -I\$(top_srcdir)" >>$OUT
echo "AM_CFLAGS = -Wall" >>$OUT
echo "${NAME}_CPPFLAGS = \$(FFTW3_CFLAGS) \$(CRYPTOPP_CFLAGS)" >>$OUT
echo "${NAME}_LDADD = \$(FFTW3_LIBS) \$(CRYPTOPP_LIBS)" >>$OUT

if [[ "$OSTYPE" == "darwin"* ]]; then
  glibtoolize --force && aclocal && autoconf && automake --add-missing
else
  libtoolize --force && aclocal && autoconf && automake --add-missing
fi
