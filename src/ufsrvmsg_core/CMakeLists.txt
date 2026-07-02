add_definitions(-DHAVE_CONFIG_H)

#[[set(CMAKE_C_CLANG_TIDY
        clang-tidy;
        -header-filter=.*;
        -checks=*,-llvmlibc-restrict-system-libc-headers;
        )]]

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}
        $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PARENT_DIR}
        ${PARENT_DIR}/include
        ${PARENT_DIR}/ufsrv_core/include
        ${PARENT_DIR}/hiredis
        /opt/include /opt/include/mysql )

#IN VIM use: :read ! ls sa/*.c
set(source
        attachments.c
        adt_locking_lru.c
        crypto_certificates.pb-c.c
        Groups.pb-c.c
        gpc_http_utils.c
        gpc_utils.c
        http_request.c
        integrity.c
        misc.c
        net.c
        session.c
        session_service.c
        session_utils.c
        sessionworkers_utils.c
        share_list.c
        SignalService.pb-c.c
        thread_utils.c
        utils_curve.c
        utils_crypto.c
        utils_db_account.c
        utils_nonce.c
        fence/fence.c
        fence/fence_events.c
        fence/fence_permission.c
        fence/fence_proto.c
        fence/fence_protobuf.c
        fence/fence_state.c
        fence/fence_utils.c
        fence/fence_utils_db.c
        system_roles.c
        type_providers/attachment_descriptor_provider.c
        type_providers/mpsc_queue_node_provider.c
        type_providers/session_provider.c
        )

add_subdirectory(msgqueue_backend)
add_subdirectory(protocol)
add_subdirectory(user)
add_subdirectory(location)
add_subdirectory(donations)

add_library(ufsrvmsg_core ${source})

set_target_properties(ufsrvmsg_core PROPERTIES OUTPUT_NAME "ufsrvmsg_core")

target_include_directories(ufsrvmsg_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Add -fPIC flag
set_property(TARGET ufsrvmsg_core PROPERTY POSITION_INDEPENDENT_CODE ON)