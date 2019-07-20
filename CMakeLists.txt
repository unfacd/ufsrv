cmake_minimum_required(VERSION 3.5)

set (PROJECT_NAME "ufsrv")

MACRO(getVersionPatchLevel name)
    SET(VERSION_REGEX "^#define ${name} (.+)$")
    FILE(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/include/version.h"
            VERSION_BIT REGEX ${VERSION_REGEX})
    STRING(REGEX REPLACE ${VERSION_REGEX} "\\1" ${name} "${VERSION_BIT}")
ENDMACRO(getVersionPatchLevel)

getVersionPatchLevel(UFSRV_MAJOR)
getVersionPatchLevel(UFSRV_MINOR)
getVersionPatchLevel(UFSRV_PATCH)
SET(VERSION "${UFSRV_MAJOR}.${UFSRV_MINOR}.${UFSRV_PATCH}")
MESSAGE("Detected ufsrv version: ${VERSION}")

project(${PROJECT_NAME} LANGUAGES C)
project(${PROJECT_NAME} VERSION "${VERSION}")


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3 -Wall -Wno-unused-label -Wno-unused-variable -Wno-comment")
#set(CMAKE_C_FLAGS_MINSIZEREL "put your flags")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -ggdb3 -Wall -Wno-unused-label -Wno-unused-variable -Wno-comment")
set(CMAKE_C_FLAGS_RELEASE "-O2 -Wall -Wno-unused-label -Wno-unused-variable -Wno-comment")

add_subdirectory(src/hiredis)
add_subdirectory(src/lzf)
add_subdirectory(src/curve25519)
add_subdirectory(src)
