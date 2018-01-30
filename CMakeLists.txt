cmake_minimum_required(VERSION 3.8)
project(codecrypt)

set(CMAKE_CXX_STANDARD 11)

if (APPLE)
    include_directories(/usr/local/opt/gmp/include /usr/local/opt/fftw/include)
    link_directories(/usr/local/opt/gmp/lib /usr/local/opt/fftw/lib)
elseif(UNIX)
    include_directories(/usr/include)
    link_directories(/usr/lib)
endif (APPLE)


add_executable(codecrypt
        src/actions.cpp
        src/actions.h
        src/algo_suite.cpp
        src/algo_suite.h
        src/algorithm.h
        src/algos_enc.cpp
        src/algos_enc.h
        src/algos_sig.cpp
        src/algos_sig.h
        src/arcfour.h
        src/base64.cpp
        src/base64.h
        src/bvector.cpp
        src/bvector.h
        src/chacha.cpp
        src/chacha.h
        src/cube_hash.h
        src/cubehash_impl.h
        src/decoding.h
        src/envelope.cpp
        src/envelope.h
        src/factoryof.h
        src/fft.cpp
        src/fft.h
        src/fmtseq.cpp
        src/fmtseq.h
        src/generator.cpp
        src/generator.h
        src/gf2m.cpp
        src/gf2m.h
        src/hash.cpp
        src/hash.h
        src/hashfile.cpp
        src/hashfile.h
        src/iohelpers.cpp
        src/iohelpers.h
        src/ios.cpp
        src/ios.h
        src/keyring.cpp
        src/keyring.h
        src/main.cpp
        src/matrix.cpp
        src/matrix.h
        src/mce_qcmdpc.cpp
        src/mce_qcmdpc.h
        src/message.cpp
        src/message.h
        src/permutation.cpp
        src/permutation.h
        src/polynomial.cpp
        src/polynomial.h
        src/prng.h
        src/qd_utils.h
        src/rmd_hash.h
        src/sc.cpp
        src/sc.h
        src/sencode.cpp
        src/sencode.h
        src/serialization.cpp
        src/sha_hash.h
        src/str_match.cpp
        src/str_match.h
        src/symkey.cpp
        src/symkey.h
        src/tiger_hash.h
        src/types.h
        src/vector_item.h
        src/xsynd.cpp
        src/xsynd.h)

target_link_libraries(codecrypt fftw3 gmp)
