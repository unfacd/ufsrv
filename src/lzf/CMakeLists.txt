include_directories(${CMAKE_CURRENT_SOURCE_DIR})

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)

add_library(lzf ${source})
set_target_properties(lzf PROPERTIES OUTPUT_NAME "lzf")

target_include_directories(lzf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})