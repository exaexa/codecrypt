cmake_minimum_required(VERSION 3.8)
project(ccr)

set(CMAKE_CXX_STANDARD 11)

if (APPLE)
    include_directories(/usr/local/opt/gmp/include /usr/local/opt/fftw/include)
    link_directories(/usr/local/opt/gmp/lib /usr/local/opt/fftw/lib)
    add_definitions(-DHAVE_READPASSPHRASE=1)

    find_library(HAVE_CRYPTOPP cryptopp)
    if(HAVE_CRYPTOPP)
        add_definitions(-DHAVE_CRYPTOPP=1)
        include_directories(/usr/local/opt/cryptopp/include)
        link_directories(/usr/local/opt/cryptopp/lib)
    else()
        message(WARNING "install cryptopp by homebrew is better")
    endif()

elseif(UNIX)
    include_directories(/usr/include)
    link_directories(/usr/lib)

    find_library(HAVE_BSDREADPASSPHRASE bsd)
    if (HAVE_BSDREADPASSPHRASE)
        add_definitions(-DHAVE_BSDREADPASSPHRASE=1)
    else()
        message(FATAL_ERROR "libbsd missing, you can install libbsd-dev package!")
    endif()

    find_library(HAVE_CRYPTOPP crypto++)
    if(HAVE_CRYPTOPP)
        add_definitions(-DHAVE_CRYPTOPP=1 -DCRYPTOPP_DIR_PLUS=1)
    else()
        message(WARNING "use crypto++ is better")
    endif()

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

target_link_libraries(ccr fftw3 gmp)

if (APPLE)
elseif(UNIX)
    if (HAVE_BSDREADPASSPHRASE)
        target_link_libraries(ccr bsd)
    endif()
endif (APPLE)

if (HAVE_CRYPTOPP)
    if(CRYPTOPP_DIR_PLUS)
        target_link_libraries(ccr crypto++)
    else()
        target_link_libraries(ccr cryptopp)
    endif()
endif ()