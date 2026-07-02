#IMPORTANT: pass -DCMAKE_USER_MAKE_RULES_OVERRIDE=c_flag_overrides.cmake to cmake to pick up the correct toolchain definitions.
cmake_minimum_required(VERSION 3.9)

set(PROJECT_NAME "ufsrv")
#set(CMAKE_VERBOSE_MAKEFILE ON)

# project based cmake modules (use include(...module_file_name_))
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)

include(CMakeFindBinUtils)#check the value of _CMAKE_TOOLCHAIN_PREFIX_INIT in file c_flag_overrides.cmake
include(CheckSymbolExists)

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

set(CMAKE_USER_MAKE_RULES_OVERRIDE ${CMAKE_CURRENT_SOURCE_DIR}/c_flag_overrides.cmake)
set(CMAKE_USER_MAKE_RULES_OVERRIDE_CXX ${CMAKE_CURRENT_SOURCE_DIR}/cxx_flag_overrides.cmake)
project(${PROJECT_NAME} LANGUAGES C ASM)
project(${PROJECT_NAME} VERSION "${VERSION}")

string(TOLOWER "${CMAKE_C_COMPILER_ID}" COMPILER_ID)
if (NOT COMPILER_ID STREQUAL "clang")
    message(FATAL_ERROR "ufsrv requires clang to build. COMPILER_ID: ${COMPILER_ID}, ${CMAKE_C_COMPILER_VERSION}")
endif()

message("Building with: ${COMPILER_ID}, ${CMAKE_C_COMPILER_VERSION}")

# check if _GNU_SOURCE is available

if (NOT _GNU_SOURCE)
    check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

    if (NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        check_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif ()
endif ()

if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif ()

set(CMAKE_C_STANDARD 11)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    SET(ASM_OPTIONS "")
    SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS_DEBUG} ${ASM_OPTIONS}" )
    add_compile_definitions(__UF_FULLDEBUG_LOCKING)
else()
    SET(ASM_OPTIONS "")
    SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS_RELEASE} ${ASM_OPTIONS}" )
endif()

#generate compilation database file: compile_commands.json for static analysis  (currently CodeChecker). turn on -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

find_path(UFLIB_INCLUDE_DIR "standard_c_includes.h")
find_library(UFLIB_LIBRARY uflib)
if(UFLIB_INCLUDE_DIR AND UFLIB_LIBRARY)
else()
    add_subdirectory(packages/uflib)
endif()
find_path(UFLIB_INCLUDE_DIR "standard_c_includes.h")
if(UFLIB_INCLUDE_DIR)
    message("found ${UFLIB_INCLUDE_DIR}")
else()
    message("not found")
endif()

add_subdirectory(src)
add_subdirectory(src/hiredis)
add_subdirectory(src/coroutines)
add_subdirectory(src/ufsrv_core)
add_subdirectory(src/ufsrvmsg_core)
add_subdirectory(src/ufsrvrest)
add_subdirectory(src/ufsrvwebsock)
add_subdirectory(src/zkgroup_utils)
add_subdirectory(src/curve25519)
add_subdirectory(src/ufsrvsfu)



file(GLOB_RECURSE ALL_C_H_FILES RELATIVE ${CMAKE_SOURCE_DIR}
        "src/*.c" "src/*.h"
        "tools/*.c" "tools/*.h"
        )
#add_custom_target(indent
#        COMMAND indent -linux -i2 -nut -brf ${ALL_C_H_FILES}
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
#        )