#!/bin/sh

# simple autogen script that generates basic layout for autotools.

COMMON_CPPFLAGS="-I/usr/local/include -I\$(srcdir)/include/"
COMMON_CFLAGS="-Wall"
COMMON_LDFLAGS="-L/usr/local/lib"
COMMON_LDADD=""

OUT=Makefile.am
touch NEWS AUTHORS ChangeLog
echo > $OUT

PROGS="ccr-keygen-rs ccr-encrypt ccr-decrypt"
DISTDIRS=""

echo "AUTOMAKE_OPTIONS = subdir-objects" >>$OUT
echo "dist_noinst_SCRIPTS = autogen.sh" `for i in $DISTDIRS ; do find \$i -type f ; done | tr "\n" " " ` >>$OUT

echo "noinst_HEADERS = `find include/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT
echo "lib_LTLIBRARIES = libcodecrypt.la" >>$OUT
echo "libcodecrypt_la_SOURCES = `(find lib/ -type f -name *.c; find lib/ -type f -name *.cpp)|tr \"\n\" \" \" ` " >>$OUT
echo "noinst_HEADERS += `find lib/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT

echo "libcodecrypt_la_CPPFLAGS = -I\$(srcdir)/lib/ ${COMMON_CPPFLAGS}" >>$OUT
echo "libcodecrypt_la_CFLAGS = ${COMMON_CFLAGS}" >>$OUT
echo "libcodecrypt_la_LDFLAGS = ${COMMON_LDFLAGS}" >>$OUT
#echo "libcodecrypt_la_LDADD = ${COMMON_LDADD} " >>$OUT
[ -f "lib/Makefile.am.extra" ] && cat "lib/Makefile.am.extra" >>$OUT

echo "bin_PROGRAMS = $PROGS" >>$OUT
for i in $PROGS 
do 
	name=`echo $i |tr '-' '_'`
	dir="src/${i#ccr-}"
	echo "${name}dir = $dir/" >>$OUT
	echo "${name}_SOURCES = `( find $dir/ -type f -name \*.c ; find $dir/ -type f -name \*.cpp ) |tr \"\n\" \" \" ` " >>$OUT
	echo "noinst_HEADERS += `find $dir/ -type f -name \*.h |tr \"\n\" \" \" `" >>$OUT
	echo "${name}_CPPFLAGS = -I\$(srcdir)/$i/ ${COMMON_CPPFLAGS}" >>$OUT
	echo "${name}_CFLAGS = ${COMMON_CFLAGS}" >>$OUT
	echo "${name}_LDFLAGS = ${COMMON_LDFLAGS}" >>$OUT
	echo "${name}_LDADD = libcodecrypt.la ${COMMON_LDADD} " >>$OUT
	[ -f "$dir/Makefile.am.extra" ] && cat "$dir/Makefile.am.extra" >>$OUT
done

libtoolize --force && aclocal && autoconf && automake --add-missing

