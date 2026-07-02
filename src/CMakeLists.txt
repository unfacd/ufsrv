set (EXEC_NAME "ufsrvapi")

add_definitions(-DHAVE_CONFIG_H)

#required by the custom command
add_custom_target(ufsrv_version ALL
        DEPENDS version.c
        COMMENT "Creating a custom build target 'ufsrv_version' for generating fresh version file"
        VERBATIM
)
add_custom_command(
        OUTPUT version.c
        DEPENDS ufsrv_version
        COMMAND chmod 755 ${CMAKE_CURRENT_SOURCE_DIR}/version.c.sh
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/version.c.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        COMMENT "Generating a version file with fresh compilation timestamp"
)

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
add_executable(${EXEC_NAME} ${source} version.c include/config_nonpublic.h)


#add_custom_command(TARGET ${EXEC_NAME}
#        # Run after sources have been compiled but before linking the binary or running the librarian or archiver tool of a static library. This is not defined for targets created by the add_custom_target() command
#        PRE_LINK
#        COMMAND echo -e "\texecuting a PRE_LINK command"
#        COMMENT "No commands defined."
#        VERBATIM
#        )
#
#add_custom_command(TARGET ${EXEC_NAME}
#        # Run after all other rules within the target have been executed
#        POST_BUILD
#        COMMAND echo -e "\texecuting a POST_BUILD command"
#        COMMENT "No commands defined."
#        VERBATIM
#        )

target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${EXEC_NAME} PRIVATE /opt/include)
target_include_directories(${EXEC_NAME} PRIVATE /opt/mysql/include)
target_include_directories(${EXEC_NAME} PUBLIC $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>)
target_include_directories(${EXEC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/hiredis/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvmsg_core/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrv_core/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvrest/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvwebsock/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ufsrvsfu/include)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/http_rest)
target_include_directories(${EXEC_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/zkgroup_utils)

#system libraries
set(THEADS_PREFER_PTHEAD_FLAG on)
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
set_target_properties(mysqlclient PROPERTIES IMPORTED_LOCATION "/opt/lib/mariadb/libmariadb.a")
add_library(zkgroup SHARED IMPORTED)
set_target_properties(zkgroup PROPERTIES IMPORTED_LOCATION "/opt/lib/libsignal_ffi.a")
add_library(jemalloc SHARED IMPORTED)
set_target_properties(jemalloc PROPERTIES IMPORTED_LOCATION "/opt/lib/libjemalloc.so")

set (PROJECT_LINK_LIBS jemalloc utf8proc lua ${CMAKE_THREAD_LIBS_INIT} nsl json-c curl ssl crypto resolv m mysqlclient zkgroup dl systemd bsd BlocksRuntime)
#link_directories(ufsrvrest ufsrvsfu ufsrvwebsock ufsrvmsg_core uflib protobuf-c http_rest zkgroup_utils recycler lzf hiredis curve25519 k12)
target_link_libraries(${EXEC_NAME} LINK_PUBLIC ufsrvrest ufsrv_core ufsrvmsg_core ufsrvsfu  ufsrvwebsock uflib zkgroup_utils hiredis coroutines curve25519 ${PROJECT_LINK_LIBS})