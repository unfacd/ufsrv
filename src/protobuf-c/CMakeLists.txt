add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
#add_subdirectory(db)

add_library(protobuf-c ${source})

set_target_properties(protobuf-c PROPERTIES OUTPUT_NAME "protobuf-c")

target_include_directories(protobuf-c PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})