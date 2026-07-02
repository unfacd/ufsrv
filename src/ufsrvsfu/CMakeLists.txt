add_definitions(-DHAVE_CONFIG_H -DMPSC_MESSAGE_QUEUE -DSFU_CODEBASE)

set (MODULE_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        crc32
        dns
        hash
        hmac
        ice
        fmt
        list
        mbuf
        mem
        net
        sa
        sa
        stun
        sys
        tmr
        udp
    )
include_directories(
                    ${MODULE_INCLUDE_DIRS}
                    /opt
                    /opt/include
                    ${CMAKE_SOURCE_DIR}/src
                    ${CMAKE_SOURCE_DIR}/src/include
                    ${CMAKE_SOURCE_DIR}/src/ufsrv_core/include
                    $<TARGET_PROPERTY:uflib,INTERFACE_INCLUDE_DIRECTORIES>
                    ${CMAKE_SOURCE_DIR}/src/ufsrvmsg_core/include
                   )

#IN VIM use: :read ! ls sa/*.c
set(SOURCES
        delegator_sfu_listener_thread.c
        delegator_sfu_worker_thread.c
        mmsg_provider.c
        protocol_sfu.c
        session_worker_sfu_thread.c
        sfu_session_provider.c

        list/list.c
        crc32/crc32.c
        dns/client.c
        dns/cstr.c
        dns/dname.c
        dns/hdr.c
        dns/ns.c
        dns/res.c
        dns/rr.c
        dns/rrlist.c
        hash/func.c
        hash/hash.c
        hmac/hmac.c
        hmac/hmac_sha1.c

        ice/cand.c
        ice/candpair.c
        ice/chklist.c
        ice/comp.c
        ice/connchk.c
        ice/ice.c
        ice/icem.c
        ice/icesdp.c
        ice/icestr.c
        ice/stunsrv.c
        ice/util.c
        fmt/ch.c
        fmt/hexdump.c
        fmt/pl.c
        fmt/print.c
        fmt/prm.c
        fmt/regex.c
        fmt/str.c
        fmt/str_error.c
        fmt/time.c
        fmt/unicode.c
        mbuf/mbuf.c
        mem/mem.c
        mem/secure.c
        net/posix/pif.c
        net/if.c
        net/ifaddrs.c
        net/net.c
        net/netstr.c
        net/rt.c
        net/sock.c
        net/sockopt.c
        sa/ntop.c
        sa/printaddr.c
        sa/pton.c
        sa/sa.c
        sdp/attr.c
        sdp/format.c
        sdp/attr.c
        sdp/format.c
        stun/addr.c
        stun/attr.c
        stun/ctrans.c
        stun/dnsdisc.c
        stun/hdr.c
        stun/ind.c
        stun/keepalive.c
        stun/msg.c
        stun/rep.c
        stun/req.c
        stun/stun.c
        stun/stunstr.c
        stun_agent/stun_agent.c
        sys/endian.c
        sys/rand.c
        tmr/tmr.c
        udp/mcast.c
        udp/udp.c
        timeout_scheduled_job_provider.c timeout_scheduled_job_provider.h)

add_library(ufsrvsfu ${SOURCES})
set_target_properties(ufsrvsfu PROPERTIES OUTPUT_NAME "ufsrvsfu")

target_include_directories(ufsrvsfu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Add -fPIC flag
set_property(TARGET ufsrvsfu PROPERTY POSITION_INDEPENDENT_CODE ON)