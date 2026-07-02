DEP_DIR    := .dep
OBJDIR     := obj
BINDIR     := bin

EFILE      := ufclt
INCLUDES   := -I./include  -I/usr/include -I./hiredis -I./lua -I/opt/include -I/opt/mysql/include -I./libsignal-protocol-c/src
SHELL      := /bin/sh
#CFLAGS     := $(INCLUDES) -g -O0 -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free -I/usr/include
CFLAGS     := $(INCLUDES) -static -g -O0 -I/usr/include
VERSION    := 0.1
#CC         := clang
CC					:= gcc
DEFS       := -DHAVE_CONFIG_H
LIBS       := -lufsrvlib -llua -lhiredis -lpthread -lnsl -ljson-c -lssl -lcrypto -lresolv -lcurl -lm -lprotobuf-c -lmysqlclient  -lsignal-protocol-c
LDFLAGS    :=	-Wl,-rpath,/opt/lib -L. -L./libsignal-protocol-c/build/src/ -L./hiredis -L./lua -L/opt/lib
INSTALL    := /usr/bin/install -c
prefix     := /usr/local
exec_prefix := ${prefix}
SBIN_DIR    := ${exec_prefix}/sbin
MAN_DIR     := ${prefix}/share/man
ETC_DIR     := ${prefix}/etc
VAR_DIR     := ${prefix}/var

STRIP      := -s
YACC	      := bison -y
LEX        := flex
YACCFLAGS  := -d
LEXFLAGS  :=

vpath %.h include

#DSOURCE      := configparse.c
#DOBJECTS	 := $(OBJDIR)/configparse.o

UFSRVLIB_LOC	:= ..
SOURCES      := $(wildcard *.c)
UFSRVLIB_SOURCES:= db_abstraction.c db_mysql.c misc.c list.c queue.c hashtable.c net.c location.c utils.c utils_crypto.c fence.c users.c protocol_io.c  protocol_websocket_routines.c protocol_websocket_io.c user_backend.c user_backend_access_wordpress.c WebSocketMessage.pb-c.c SignalService.pb-c.c
UFSRVLIB_OBJECTS      := $(patsubst %.c,$(UFSRVLIB_LOC)/obj/%.o,$(UFSRVLIB_SOURCES))

OBJECTS      := $(patsubst %.c,$(OBJDIR)/%.o,$(SOURCES))
DEP_FILES    := $(patsubst %.c,$(DEP_DIR)/%.d,$(SOURCES))


SOURCES		 := $(SOURCES) $(DSOURCE)
OBJECTS		 := $(OBJECTS) $(DOBJECTS)
#
# Cancel built-in implicit rule for %.o
#
%.o : %.c

#
#Redifine the implicit rule fo %.o
#
$(OBJDIR)/%.o : %.c
	$(CC) -c -Wall $(CFLAGS) $(DEFS) $< -o $@


.PHONY: all
all : whatsup version ufsrvlib $(EFILE)


$(EFILE): $(OBJECTS)
	@echo
	@echo " Linking object files..."
	@echo
	$(CC)  $(LDFLAGS) $^ -o $(BINDIR)/$(EFILE) $(LIBS)


include $(DEP_FILES)


.PHONY: whatsup
whatsup:
	@echo
	@echo " `date '+ %A, %d %B %Y'`"
	@echo " Generating object files for $(EFILE) $(VERSION)..."
	@echo
#	@if [ -r configparse.y ]; then \
		$(YACC) $(YACCFLAGS) -o configparse.c configparse.y; \
		cd include; ln -sf ../configparse.h .; \
		cd ..; \
	else \
		echo "Missing grammar file..."; \
		exit; \
	fi

$(DEP_DIR)/%.d: %.c
	$(SHELL) -ec '$(CC) -M $(CFLAGS) $< \
       | sed '\''s/\($*\)\.o[ :]*/$(OBJDIR)\/\1.o $(@D)\/$(@F) : /g'\'' > $@; \
       [ -s $@ ] || rm -f $@'


.PHONY: version
version:
	@chmod 755 version.c.in; ./version.c.in


.PHONY: tags
tags:
	@echo "Updating tags file..."
	@ctags --recurse=yes --sort=yes *.[ch]

.PHONY: ufsrvlib
ufsrvlib:
	@echo "UFSRVLIB FILES: $(UFSRVLIB_OBJECTS)" 
	@ar rcs libufsrvlib.a $(UFSRVLIB_OBJECTS)

.PHONY: clean
clean:
	rm -rf obj/*.o
	rm -rf .dep/*.d
	rm -rf ../bin/*
	rm -rf core *.core *.a *.so
