add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}
        $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PARENT_DIR}
        ${PARENT_DIR}/include
        ${PARENT_DIR}/hiredis
        ${PARENT_DIR}/ufsrvmsg_core/include
        ${PARENT_DIR}/ufsrvmsg_core
        /opt/include /opt/include/mysql )

set(source
        delegator_session_io_worker_thread.c
        delegator_timer_thread.c
        cache_backend/persistance.c
        cache_backend/persistance.h
        cache_backend/persistance_type.h
        cache_backend/redis.h
        cache_backend/redis.c
        cache_backend/redis_backend_type.h
        jobworkers/jobworkers_utils.c
        jobworkers/user_callback_job.c
        jobworkers/worker_ufsrv_thread.c
)

add_subdirectory(instrumentation)
add_subdirectory(ratelimit)
add_subdirectory(http)

add_library(ufsrv_core ${source})

set_target_properties(ufsrv_core PROPERTIES OUTPUT_NAME "ufsrv_core")

target_include_directories(ufsrv_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Add -fPIC flag
set_property(TARGET ufsrv_core PROPERTY POSITION_INDEPENDENT_CODE ON)