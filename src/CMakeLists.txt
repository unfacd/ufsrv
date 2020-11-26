set (EXEC_NAME "ufsrvapi")

add_definitions(-DHAVE_CONFIG_H)

add_custom_target (
        ufsrv_version
        COMMAND chmod 755 ${CMAKE_CURRENT_SOURCE_DIR}/version.c.sh
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/version.c.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
add_executable(${EXEC_NAME} ${source} include/config_nonpublic.h)
add_dependencies(${EXEC_NAME} ufsrv_version)
target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${EXEC_NAME} PRIVATE /opt/include)
target_include_directories(${EXEC_NAME} PRIVATE /opt/mysql/include)
target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/hiredis/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/uflib/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrv_core/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvrest/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvwebsock/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/http_rest)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/recycler)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/zkgroup_utils)

#system libraries
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

#package libraries
add_library(utf8proc SHARED IMPORTED)
set_target_properties(utf8proc PROPERTIES IMPORTED_LOCATION "/opt/lib/libutf8proc.so")
add_library(lua STATIC IMPORTED)
set_target_properties(lua PROPERTIES IMPORTED_LOCATION "/opt/lib/liblua.a")
add_library(json-c SHARED IMPORTED)
set_target_properties(json-c PROPERTIES IMPORTED_LOCATION "/opt/lib/libjson-c.so")
add_library(curl STATIC IMPORTED)
set_target_properties(curl PROPERTIES IMPORTED_LOCATION "/opt/lib/libcurl.a")
add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION "/opt/lib/libssl.a")
add_library(crypto STATIC IMPORTED include/config_nonpublic.h)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION "/opt/lib/libcrypto.a")
add_library(mysqlclient SHARED IMPORTED)
set_target_properties(mysqlclient PROPERTIES IMPORTED_LOCATION "/opt/lib/libmysqlclient.so")
add_library(zkgroup SHARED IMPORTED)
set_target_properties(zkgroup PROPERTIES IMPORTED_LOCATION "/opt/lib/libzkgroup.so")

set (PROJECT_LINK_LIBS utf8proc lua ${CMAKE_THREAD_LIBS_INIT} nsl json-c curl ssl crypto resolv m mysqlclient zkgroup dl systemd bsd)

target_link_libraries(${EXEC_NAME} LINK_PUBLIC ufsrvrest ufsrvwebsock ufsrv_core uflib protobuf-c http_rest zkgroup_utils recycler lzf hiredis curve25519 k12 ${PROJECT_LINK_LIBS})