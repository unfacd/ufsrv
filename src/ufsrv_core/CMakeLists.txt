add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include ${PARENT_DIR} ${PARENT_DIR}/include ${PARENT_DIR}/uflib/include ${PARENT_DIR}/hiredis /opt/include /opt/include/mysql )

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
add_subdirectory(cache_backend)
add_subdirectory(msgqueue_backend)
add_subdirectory(fence)
add_subdirectory(protocol)
add_subdirectory(ratelimit)
add_subdirectory(user)
add_subdirectory(instrumentation)
add_subdirectory(location)

add_library(ufsrv_core ${source})

set_target_properties(ufsrv_core PROPERTIES OUTPUT_NAME "ufsrv_core")

target_include_directories(ufsrv_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})