add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include ${PARENT_DIR} ${PARENT_DIR}/include ${PARENT_DIR}/uflib/include ${PARENT_DIR}/ufsrv_core/include ${PARENT_DIR}/protobuf-c ${PARENT_DIR}/hiredis /opt/include /opt/include/mysql )

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
#add_subdirectory(db)

add_library(ufsrvrest ${source})

set_target_properties(ufsrvrest PROPERTIES OUTPUT_NAME "ufsrvrest")

target_include_directories(ufsrvrest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})