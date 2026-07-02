#cmake -S . -B build/ -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_USER_MAKE_RULES_OVERRIDE=c_flag_overrides.cmake -DCMAKE_TOOLCHAIN_FILE=clang_linux_toolchain.cmake
#cmake --build build --

#DONT USE _FORTIFY_SOURCE: Currently ASan (and other sanitizers) doesn't support source fortification.
#-fsanitize=address -fsanitize=nonnull-attribute -fsanitize=bool not compatible wih valgrind
option(UFSRV_BUILD_WITH_MSAN "Build with MemorySanitizer instrumentation" OFF)
set(CMAKE_UFSRV_MSAN_FLAGS
        "-fPIE -fno-omit-frame-pointer -fsanitize-blacklist=/home/devops/ufsrvapi/sanitizer_ignorelist.clang -fsanitize-ignorelist=/home/devops/ufsrvapi/sanitizer_ignorelist.clang -fstack-protector-all  -fsanitize-memory-track-origins -fsanitize-recover -fsanitize=memory,signed-integer-overflow,integer-divide-by-zero,null,enum,alignment,unreachable,bounds -fsanitize=vptr -fsanitize=return"
        CACHE STRING
        "Flags used for turning on MemorySanitizer" FORCE
        )
option(UFSRV_BUILD_WITH_ASAN "Build with AddressSanitizer instrumentation" OFF)
set(CMAKE_UFSRV_ASAN_FLAGS
        "-fno-omit-frame-pointer -fsanitize=address,signed-integer-overflow"
        CACHE STRING
        "Flags used for turning on AddressSanitizer" FORCE
        )
option(UFSRV_BUILD_WITH_MSAN "Build with ThreadSanitizer instrumentation" OFF)
set(CMAKE_UFSRV_TSAN_FLAGS
        "-fno-omit-frame-pointer -fsanitize=thread"
        CACHE STRING
        "Flags used for turning on ThreadSanitizer" FORCE
        )
if (UFSRV_BUILD_WITH_MSAN AND UFSRV_BUILD_WITH_ASAN)
    message(FATAL_ERROR "Cannot build with both, UFSRV_BUILD_WITH_MSAN and UFSRV_BUILD_WITH_ASAN")
endif()

if (UFSRV_BUILD_WITH_MSAN)
    set(UFSRV_SANITIZER_FLAGS "${CMAKE_UFSRV_MSAN_FLAGS}")
    unset(UFSRV_BUILD_WITH_MSAN CACHE)
elseif(UFSRV_BUILD_WITH_ASAN)
    set(UFSRV_SANITIZER_FLAGS "${CMAKE_UFSRV_ASAN_FLAGS}")
    unset(UFSRV_BUILD_WITH_ASAN CACHE)
endif()

#-Xclang -analyzer-config -Xclang unix.DynamicMemoryModeling:Optimistic=true
#required in order for the Clang Static Analyzer to acknowledge the ownership_takes,,ownership_holds etc attributes, the Optimistic config needs to be set to true for the checker
SET (CMAKE_C_FLAGS_INIT                "-fblocks -fprofile-arcs -ftest-coverage -Wall -Wno-unused-label -Wno-nullability-completeness -Wno-unused-variable -Wno-comment -Wimplicit-fallthrough -Wno-deprecated-non-prototype -Wno-unknown-attributes -std=c11 -Xclang -analyzer-config -Xclang unix.DynamicMemoryModeling:Optimistic=true")
SET (CMAKE_C_FLAGS_DEBUG_INIT          "-O0 -ggdb3 ${UFSRV_SANITIZER_FLAGS}")
SET (CMAKE_C_FLAGS_MINSIZEREL_INIT     "-Os -DNDEBUG")
SET (CMAKE_C_FLAGS_RELEASE_INIT        "-O3 -lto -DNDEBUG")
SET (CMAKE_C_FLAGS_RELWITHDEBINFO_INIT "-O2 -g")
SET (_CMAKE_TOOLCHAIN_PREFIX_INIT      "llvm-")
set(CMAKE_EXE_LINKER_FLAGS_INIT        "-fuse-ld=lld")
set(CMAKE_MODULE_LINKER_FLAGS_INIT     "-fuse-ld=lld")
set(CMAKE_SHARED_LINKER_FLAGS_INIT     "-fuse-ld=lld")