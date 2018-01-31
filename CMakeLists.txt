cmake_minimum_required(VERSION 3.8)
project(ccr)

set(CMAKE_CXX_STANDARD 11)

if (APPLE)
    include_directories(/usr/local/opt/gmp/include /usr/local/opt/fftw/include)
    link_directories(/usr/local/opt/gmp/lib /usr/local/opt/fftw/lib)
    add_definitions(-DHAVE_READPASSPHRASE=1)
elseif(UNIX)
    include_directories(/usr/include)
    link_directories(/usr/lib)
    add_definitions(-DHAVE_BSDREADPASSPHRASE=1)
endif (APPLE)

add_definitions(-DPACKAGE_VERSION="1.8")

add_executable(ccr
        src/actions.cpp
        src/algo_suite.cpp
        src/algos_enc.cpp
        src/algos_sig.cpp
        src/base64.cpp
        src/bvector.cpp
        src/chacha.cpp
        src/envelope.cpp
        src/fft.cpp
        src/fmtseq.cpp
        src/generator.cpp
        src/gf2m.cpp
        src/hash.cpp
        src/hashfile.cpp
        src/iohelpers.cpp
        src/ios.cpp
        src/keyring.cpp
        src/main.cpp
        src/matrix.cpp
        src/mce_qcmdpc.cpp
        src/message.cpp
        src/permutation.cpp
        src/privfile.cpp
        src/polynomial.cpp
        src/sc.cpp
        src/seclock.cpp
        src/sencode.cpp
        src/serialization.cpp
        src/str_match.cpp
        src/symkey.cpp
        src/pwrng.cpp
        src/xsynd.cpp)

if (APPLE)
    target_link_libraries(ccr fftw3 gmp)
elseif(UNIX)
    target_link_libraries(ccr fftw3 gmp bsd)
endif (APPLE)
