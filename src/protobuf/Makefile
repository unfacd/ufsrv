default:
	@echo "Generating protobuf compiled files for SignalService.proto..."
	@if [ -r SignalService.proto ]; then \
		mv SignalService.pb-c.c SignalService.pb-c.c.old;	\
		mv SignalService.pb-c.h SignalService.pb-c.h.old;	\
		/opt/bin/protoc-c --c_out=. SignalService.proto;	\
		if [ -r SignalService.pb-c.c ]; then \
    	cp SignalService.pb-c.c ..; \
    	cp SignalService.pb-c.h ../include/; \
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
    	cp crypto_certificates.pb-c.c ..; \
    	cp crypto_certificates.pb-c.h ../include/; \
  	else \
   	 echo "Error generating compiled protobuf files..."; \
    	exit; \
  	fi	\
	else	\
		echo "Error: No source protobuf file crypto_certificates.proto..."; \
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
