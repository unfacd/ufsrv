get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include ${PARENT_DIR} /opt/include /opt/include/mysql )

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
add_subdirectory(db)
add_subdirectory(adt)
add_subdirectory(scheduled_jobs)

add_library(uflib ${source})

set_target_properties(uflib PROPERTIES OUTPUT_NAME "uflib")

target_include_directories(uflib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})