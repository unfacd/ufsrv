default:
	@echo "Generating protobuf compiled files for SignalService.proto..."
	@if [ -r SignalService.proto ]; then \
		mv SignalService.pb-c.c SignalService.pb-c.c.old;	\
		mv SignalService.pb-c.h SignalService.pb-c.h.old;	\
		/opt/bin/protoc-c --c_out=. SignalService.proto;	\
		if [ -r SignalService.pb-c.c ]; then \
    			cp SignalService.pb-c.c ../src/ufsrvmsg_core; \
    			cp SignalService.pb-c.h ../src/ufsrvmsg_core; \
    			echo "Add #include <uflib/protobuf-c/protobuf-c.h> to ufsrvmsg_core/SignalService.pb-c.h" \
  		else \
   	 		echo "Error generating compiled protobuf files..."; \
    			exit; \
  	fi	\
	else	\
		echo "Error: No source protobuf file SignalService.proto..."; \
	fi

certificates:
	@echo "Generating protobuf compiled files for crypto_certificates.proto..."
	@if [ -r crypto_certificates.proto ]; then \
		mv crypto_certificates.pb-c.c crypto_certificates.pb-c.c.old;	\
		mv crypto_certificates.pb-c.h crypto_certificates.pb-c.h.old;	\
		/opt/bin/protoc-c --c_out=. crypto_certificates.proto;	\
		if [ -r crypto_certificates.pb-c.c ]; then \
    	cp crypto_certificates.pb-c.c ../src; \
    	cp crypto_certificates.pb-c.h ../src/include/; \
  	else \
   	 echo "Error generating compiled protobuf files..."; \
    	exit; \
  	fi	\
	else	\
		echo "Error: No source protobuf file crypto_certificates.proto..."; \
	fi

groups:
	@echo "Generating protobuf compiled files for Groups.proto..."
	@if [ -r Groups.proto ]; then \
		mv Groups.pb-c.c Groups.pb-c.c.old;	\
		mv Groups.pb-c.h Groups.pb-c.h.old;	\
		/opt/bin/protoc-c --c_out=. Groups.proto;	\
		if [ -r Groups.pb-c.c ]; then \
    	cp Groups.pb-c.c ../src; \
    	cp Groups.pb-c.h ../src/include/; \
  	else \
   	 echo "Error generating compiled protobuf files..."; \
    	exit; \
  	fi	\
	else	\
		echo "Error: No source protobuf file Groups.proto..."; \
	fi

msgqueue:
	@echo "Generating protobuf compiled files for UfsrvMessageQueue.proto..."
	@if [ -r UfsrvMessageQueue.proto ]; then \
                mv UfsrvMessageQueue.pb-c.c UfsrvMessageQueue.pb-c.c.old;   \
                mv UfsrvMessageQueue.pb-c.h UfsrvMessageQueue.pb-c.h.old;   \
                /opt/bin/protoc-c --c_out=. UfsrvMessageQueue.proto;  \
                if [ -r UfsrvMessageQueue.pb-c.c ]; then \
	cp UfsrvMessageQueue.pb-c.c ..; \
	cp UfsrvMessageQueue.pb-c.h ../include/; \
	else \
         echo "Error generating compiled protobuf files..."; \
        exit; \
        fi      \
	else    \
		echo "Error: No source protobuf file UfsrvMessageQueue.proto..."; \
	fi

websocket:
	@echo "Generating protobuf compiled files for WebSocketMessage.proto..."
	@if [ -r WebSocketMessage.proto ]; then \
		mv WebSocketMessage.pb-c.c WebSocketMessage.pb-c.c.old;	\
		mv WebSocketMessage.pb-c.h WebSocketMessage.pb-c.h.old;	\
		/opt/bin/protoc-c --c_out=. WebSocketMessage.proto;	\
		if [ -r WebSocketMessage.pb-c.c ]; then \
    	cp WebSocketMessage.pb-c.c ..; \
    	cp WebSocketMessage.pb-c.h ../include/; \
  	else \
   	 echo "Error generating compiled protobuf files..."; \
    	exit; \
  	fi	\
	else	\
		echo "Error: No source protobuf file WebSocketMessage.proto..."; \
	fi
