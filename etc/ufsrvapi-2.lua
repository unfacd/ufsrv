--ufsrvapi specific
intra_ufsrv_classname="ufsrv"

-- end ufsrvapi specific

server_id="1"
server_cpu_affinity=-1
main_listener_port=20081
--main_listener_bind_address="139.162.1.245"
main_listener_bind_address="127.0.0.1"
main_listener_protocol_id=1
command_console_port=20703
command_console_bind_address="127.0.0.1"
ufsrvmsgqueue_bind_address="ufsrvmsgqueue.unfacd.com"
ufsrvmsgqueue_port=6380
ufsrv_media_upload_uri="https://api.unfacd.io:20080/"

ufsrv_user_timeouts={
											unauthenticated_timeout=60, 
											connected_timeout=120, 
											suspended_timeout=60, 
											locationless_timeout=300
										}

ufsrv_buffer_sizes={
                      incoming_buffer_size=1024,
                      outgoing_buffer_size=1024,
                      holding_buffer_size=1024
                    }

-- console 
ufsrv_ssl={
						location="", 
						certificate="ufsrv_certificate_key.pem", 
						key="ufsrv_certificate_key.pem"
					}
ufsrv_ssl_command_console={required=1, client_certifcate=1}

-- client 
ufsrv_user_ssl={
            location="",
            certificate="ufsrv_certificate_key.pem",
            key="ufsrv_certificate_key.pem",
						required=1
          }

ufsrv_db_backend={
  port=19800,
  address="db.ufsrv.unfacd.com",
  username="ufsrv_user",
  password="c"
}

--statsd instrumentation backend
ufsrv_stats_backend={ip_address="127.0.0.1", port=8125}

ufsrv_geoip_backend = {
  ip_address="127.0.0.1", port=19801
}

--data persistance backend
ufsrv_persistance_backend={ address="ufsrvpersistance.unfacd.com",                                                     port=19705,
                            mode="tcp",
                            timeout=500000}

--data persistance backend
ufsrv_cache_backend_usrmsg={ address="usrmsg.cachebackend.unfacd.io",
                            port=22001,
                            mode="tcp",
                            timeout=500000
}

--data persistance backend
ufsrv_cache_backend_fence={ address="fence.cachebackend.unfacd.io",
                            port=32001,
                            mode="tcp",
                            timeout=500000
}

--thread pools
ufsrv_workers_thread_pool=3

--how many workers to spwn to service client sessions
session_workers_thread_pool=2
--log_mask=
