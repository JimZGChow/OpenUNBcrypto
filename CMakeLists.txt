cmake_minimum_required (VERSION 3.8)

project (OpneUNB_chiper VERSION 1.0.0)

link_libraries(akrypt)
link_libraries(akrypt-base)
link_libraries(crypto)

OPTION(AES128 "AES128 encrypt" ON)
OPTION(AES256 "AES256 encrypt" ON)
OPTION(KUZNECHIK "KUZNECHIK encrypt" OFF)
OPTION(MAGMA "MAGMA encrypt" OFF)

IF(AES128)
    message("AES128 ON")
    add_definitions(-DAES128)
    remove_definitions(-DAES256)
    remove_definitions(-DKUZNECHIK)
    remove_definitions(-DMAGMA)

    set(AES256 OFF)
    set(KUZNECHIK OFF)
    set(MAGMA OFF)
ENDIF(AES128)

IF(AES256)
    message("AES256 ON")
    add_definitions(-DAES256)
    remove_definitions(-DAES128)
    remove_definitions(-DKUZNECHIK)
    remove_definitions(-DMAGMA)

    set(AES128 OFF)
    set(KUZNECHIK OFF)
    set(MAGMA OFF)
ENDIF(AES256)

IF(KUZNECHIK)
    message("KUZNECHIK ON")
    add_definitions(-DKUZNECHIK)
    remove_definitions(-DAES128)
    remove_definitions(-DAES256)
    remove_definitions(-DMAGMA)

    set(AES256 OFF)
    set(AES128 OFF)
    set(MAGMA OFF)
ENDIF(KUZNECHIK)

IF(MAGMA)
    message("MAGMA ON")
    add_definitions(-DMAGMA)
    remove_definitions(-DAES128)
    remove_definitions(-DKUZNECHIK)
    remove_definitions(-DAES258)

    set(AES256 OFF)
    set(KUZNECHIK OFF)
    set(AES128 OFF)
ENDIF(MAGMA)

add_library(openUNBCryptLib SHARED  "src/aes.cpp" "includePrivate/aes.h"
                                    "src/OpenUNBDecrypterLL.cpp" "include/OpenUNBDecrypterLL.h"
                                    "src/OpenUNBDecrypterHL.cpp" "include/OpenUNBDecrypterHL.h"
                                    "src/OpenUNBEncrypterLL.cpp" "include/OpenUNBEncrypterLL.h"
                                    "src/OpenUNBEncrypterHL.cpp" "include/OpenUNBEncrypterHL.h"
                                    "src/crc24.cpp" "include/crc24.h"
                                    "include/OpenUNBTypes.h" "include/OpenUNBConsts.h")

include_directories(include/ includePrivate/)

add_executable (openUNBCryptTest "test/openUNB_encrypter.cpp")
target_link_libraries (openUNBCryptTest LINK_PUBLIC openUNBCryptLib)

install(DIRECTORY include/ DESTINATION /usr/include/OpenUNB)
install(TARGETS openUNBCryptLib DESTINATION /usr/lib)
