#necessary to include independent module uflib
get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include ${PARENT_DIR} ${PARENT_DIR}/uflib/include /opt/include /opt/include/mysql)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)

add_library(zkgroup_utils ${source})

set_target_properties(zkgroup_utils PROPERTIES OUTPUT_NAME "zkgroup_utils")

target_include_directories(zkgroup_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})