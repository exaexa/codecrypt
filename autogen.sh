#!/bin/sh

# simple autogen script that generates basic layout for autotools.

COMMON_CPPFLAGS="-I/usr/local/include"
COMMON_CFLAGS="-Wall"
COMMON_CXXFLAGS="${COMMON_CFLAGS}"
COMMON_LDFLAGS="-L/usr/local/lib"
COMMON_LDADD=""

OUT=Makefile.am
touch NEWS AUTHORS ChangeLog
echo > $OUT

DISTDIRS=""

echo "AUTOMAKE_OPTIONS = subdir-objects" >>$OUT
echo "dist_man_MANS = man/ccr.1" >>$OUT
echo "dist_noinst_SCRIPTS = autogen.sh" `for i in $DISTDIRS ; do find \$i -type f ; done | tr "\n" " " ` >>$OUT

echo "bin_PROGRAMS = ccr" >>$OUT
echo "ccrdir = src/" >>$OUT
echo "ccr_SOURCES = `( find src/ -type f -name \*.c ; find src/ -type f -name \*.cpp ) |tr \"\n\" \" \" ` " >>$OUT
echo "noinst_HEADERS = `find src/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT
echo "ccr_CPPFLAGS = -I\$(srcdir)/$i/ ${COMMON_CPPFLAGS}" >>$OUT
echo "ccr_CFLAGS = ${COMMON_CFLAGS}" >>$OUT
echo "ccr_CXXFLAGS = ${COMMON_CXXFLAGS}" >>$OUT
echo "ccr_LDFLAGS = ${COMMON_LDFLAGS}" >>$OUT
echo "ccr_LDADD = -lgmp ${COMMON_LDADD} " >>$OUT

libtoolize --force && aclocal && autoconf && automake --add-missing

