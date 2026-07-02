add_definitions(-DHAVE_CONFIG_H -DACO_USE_VALGRIND -DACO_USE_ASAN)
set (MODULE_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
)
include_directories(
        ${MODULE_INCLUDE_DIRS}
        /opt
        /opt/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/include
        ${CMAKE_SOURCE_DIR}/src/ufsrv_core/include
        $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>
        ${CMAKE_SOURCE_DIR}/src/ufsrvmsg_core/include
)
set(SOURCES
        coroutine_run_context_provider.c
    )

add_library(coroutines ${SOURCES})
set_target_properties(coroutines PROPERTIES OUTPUT_NAME "libaco")

target_include_directories(coroutines PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Add -fPIC flag
set_property(TARGET coroutines PROPERTY POSITION_INDEPENDENT_CODE ON)