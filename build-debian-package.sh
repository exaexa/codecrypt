#!/bin/sh

# run this in source directory to easily make the debian package&pals.
# be sure the source is configured before running.

if [ -z "$1" ] ; then
	echo "usage: $0 <version>"
	echo "e.g.: $0 0.1.2"
	exit 1
fi

OUT_DIR=debian-packages
N="codecrypt"
V="$1"
NV="$N-$V"
DIST="$NV.tar.gz"
ORIG="$OUT_DIR/${N}_$V.orig.tar.gz"

mkdir -p "$OUT_DIR" && \
make dist && \
cp "$DIST" "$ORIG" && \
tar xzf "$DIST" -C "$OUT_DIR" && \
cp -a debian "$OUT_DIR/$NV/" && \
cd "$OUT_DIR/$NV" && \
debuild && \
cd .. && \
rm -r "$NV" && \
echo "ready?"
