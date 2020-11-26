#the include is limited to one variant (plain64). If optimised is desired, Plain64 must be removed di to conflict in namespace
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    Plain64
)

#https://github.com/XKCP/K12
set(Inplace32BI_SRCS
        Inplace32BI/KeccakP-1600-inplace32BI.c
)
set(Optimized64_SRCS
        Optimized64/KeccakP-1600-opt64.c
)
set(Plain64_SRCS
        Plain64/KeccakP-1600-plain64.c
)
set(K12_SRCS
        KangarooTwelve.c
)
#[[set(Inplace32BI_SRCS
        Inplace32BI/KeccakP-1600-inplace32BI.c
)

set(Optimized64_SRCS
    Optimized64/KeccakP-1600-AVX2.s
    Optimized64/KeccakP-1600-AVX512.s
    Optimized64/KeccakP-1600-AVX512-plainC.c
    Optimized64/KeccakP-1600-opt64.c
    Optimized64/KeccakP-1600-runtimeDispatch.c
    Optimized64/KeccakP-1600-timesN-AVX2.c
    Optimized64/KeccakP-1600-timesN-AVX512.c
    Optimized64/KeccakP-1600-timesN-SSSE3.c
)

set(Plain64_SRCS
        Plain64/KeccakP-1600-plain64.c
)

set(K12_SRCS
        KangarooTwelve.c
)]]

add_library(k12 ${Optimized64_SRCS} ${Plain64_SRCS} ${K12_SRCS} )
set_target_properties(k12 PROPERTIES OUTPUT_NAME "k12")
target_include_directories(k12 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Add -fPIC flag
if(BUILD_SHARED_LIBS)
    set_property(TARGET k12 PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
