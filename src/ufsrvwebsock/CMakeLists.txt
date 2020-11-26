add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include ${PARENT_DIR} ${PARENT_DIR}/include ${PARENT_DIR}/uflib/include ${PARENT_DIR}/ufsrv_core/include ${PARENT_DIR}/hiredis /opt/include /opt/include/mysql )

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
add_subdirectory(command_parser)
add_subdirectory(websock_parser)

add_library(ufsrvwebsock ${source})

set_target_properties(ufsrvwebsock PROPERTIES OUTPUT_NAME "ufsrvwebsock")

target_include_directories(ufsrvwebsock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})