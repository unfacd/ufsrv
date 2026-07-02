
include_directories(${CMAKE_CURRENT_SOURCE_DIR}
        $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PARENT_DIR}
        ${PARENT_DIR}/include
        /opt/include /opt/include/mysql )
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} DB_SUB_SOURCES)
set(source ${source} ${DB_SUB_SOURCES} PARENT_SCOPE)