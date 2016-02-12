#!/bin/bash

# Run this in source directory to easily make the debian package&pals. Be sure
# the source is ./configured before running. Latest upstream version ($V here)
# in debian/changelog must be equal to the version listed in configure.ac.

OUT_DIR=debian-packages
N=`dpkg-parsechangelog --show-field Source`
VD=`dpkg-parsechangelog --show-field Version`
V="${VD%-*}"
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
echo "READY?" #z80?
