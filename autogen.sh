#!/bin/bash

# simple autogen script that generates basic layout for autotools.

NAME="ccr"
COMMON_CPPFLAGS="-I/usr/local/include"
COMMON_CFLAGS="-Wall"
COMMON_CXXFLAGS="${COMMON_CFLAGS} -std=c++11"
COMMON_LDFLAGS="-L/usr/local/lib"
COMMON_LDADD=""

OUT=Makefile.am
touch NEWS AUTHORS ChangeLog
echo > $OUT

DISTDIRS=""

echo "AUTOMAKE_OPTIONS = subdir-objects" >>$OUT
echo "ACLOCAL_AMFLAGS = -I m4" >>$OUT
echo "dist_man_MANS = man/${NAME}.1" >>$OUT
echo "dist_noinst_SCRIPTS = autogen.sh" `for i in $DISTDIRS ; do find \$i -type f ; done | tr "\n" " " ` >>$OUT

echo "bin_PROGRAMS = ${NAME}" >>$OUT
echo "${NAME}dir = src/" >>$OUT
echo "${NAME}_SOURCES = `( find src/ -type f -name \*.c ; find src/ -type f -name \*.cpp ) |tr \"\n\" \" \" ` " >>$OUT
echo "noinst_HEADERS = `find src/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT
echo "${NAME}_CPPFLAGS = -I\$(srcdir)/$i/ ${COMMON_CPPFLAGS}" >>$OUT
echo "${NAME}_CFLAGS = ${COMMON_CFLAGS}" >>$OUT
echo "${NAME}_CXXFLAGS = ${COMMON_CXXFLAGS}" >>$OUT
echo "${NAME}_LDFLAGS = ${COMMON_LDFLAGS} \$(CRYPTOPP_CFLAGS) " >>$OUT
echo "${NAME}_LDADD = -lgmp -lfftw3 -lm \$(CRYPTOPP_LIBS) ${COMMON_LDADD} " >>$OUT

if [[ "$OSTYPE" == "darwin"* ]]; then
  glibtoolize --force && aclocal && autoconf && automake --add-missing
else
  libtoolize --force && aclocal && autoconf && automake --add-missing
fi
