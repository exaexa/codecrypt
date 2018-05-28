AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

dist_man_MANS = man/ccr.1
dist_noinst_SCRIPTS = autogen.sh
bin_PROGRAMS = ccr

ccr_SOURCES = src/hash.cpp src/sencode.cpp src/gf2m.cpp src/chacha.cpp src/algo_suite.cpp src/fft.cpp src/hashfile.cpp src/symkey.cpp src/bvector.cpp src/str_match.cpp src/keyring.cpp src/ios.cpp src/algos_enc.cpp src/message.cpp src/sc.cpp src/envelope.cpp src/permutation.cpp src/mce_qcmdpc.cpp src/pwrng.cpp src/xsynd.cpp src/serialization.cpp src/generator.cpp src/iohelpers.cpp src/main.cpp src/actions.cpp src/polynomial.cpp src/algos_sig.cpp src/matrix.cpp src/seclock.cpp src/base64.cpp src/privfile.cpp src/fmtseq.cpp
noinst_HEADERS = src/str_match.h src/permutation.h src/rmd_hash.h src/fft.h src/mce_qcmdpc.h src/hash.h src/algo_suite.h src/message.h src/symkey.h src/polynomial.h src/gf2m.h src/factoryof.h src/keyring.h src/sc.h src/fmtseq.h src/cube_hash.h src/xsynd.h src/arcfour.h src/sencode.h src/sha_hash.h src/prng.h src/tiger_hash.h src/generator.h src/decoding.h src/iohelpers.h src/cubehash_impl.h src/algorithm.h src/ios.h src/bvector.h src/hashfile.h src/actions.h src/types.h src/pwrng.h src/algos_sig.h src/matrix.h src/chacha.h src/algos_enc.h src/privfile.h src/vector_item.h src/base64.h src/envelope.h src/seclock.h

AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = -Wall

ccr_CPPFLAGS = $(FFTW3_CFLAGS) $(CRYPTOPP_CFLAGS)
ccr_LDADD = $(FFTW3_LIBS) $(CRYPTOPP_LIBS)
