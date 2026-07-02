add_definitions(-DHAVE_CONFIG_H)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES> ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/http ${PARENT_DIR} ${PARENT_DIR}/include ${PARENT_DIR}/uflib/include ${PARENT_DIR}/ufsrv_core/include ${PARENT_DIR}/ufsrvmsg_core/include ${PARENT_DIR}/protobuf-c ${PARENT_DIR}/hiredis /opt/include /opt/include/mysql )

set(source
        api_endpoint_v1_account.c
        api_endpoint_v1_receipt.c
        api_endpoint_v1_server.c
        api_endpoint_v1_call.c
        api_endpoint_v1_donation.c
        api_endpoint_v1_fence.c
        api_endpoint_v1_message.c
        api_endpoint_v1_registery.c
        api_endpoint_v1_user.c
        fence_info_utils.c
        fence_protobuf.c
        fence_zkgroup_utils.c
        protocol_http.c
        protocol_http_attachments.c
        protocol_http_basic_auth.c
        protocol_http_io.c
        protocol_http_session.c
        protocol_http_user.c
    )

add_library(ufsrvrest ${source})

set_target_properties(ufsrvrest PROPERTIES OUTPUT_NAME "ufsrvrest")

target_include_directories(ufsrvrest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})