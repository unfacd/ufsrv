DEP_DIR    	:= .dep
OBJDIR     	:= obj
BINDIR     	:= bin

EFILE      	:= lzf
INCLUDES   	:= -I.
SHELL      	:= /bin/sh
#CFLAGS     := $(INCLUDES) -g -O0 -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free -I/usr/include
CFLAGS     	:= $(INCLUDES) -static -g -O0
VERSION    	:= 0.1
CC					:= gcc
DEFS       	:= -DHAVE_CONFIG_H
LIBS       	:= 
LDFLAGS    	:=	-Wl,-rpath,/opt/lib -L. -L/opt/lib
INSTALL    	:= /usr/bin/install -c
prefix     	:= /usr/local
exec_prefix := ${prefix}
SBIN_DIR    := ${exec_prefix}/sbin
MAN_DIR     := ${prefix}/share/man
ETC_DIR     := ${prefix}/etc
VAR_DIR     := ${prefix}/var

STRIP      	:= -s

vpath %.h include

SOURCES      := $(wildcard *.c)
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
all : whatsup $(EFILE)


$(EFILE): $(OBJECTS)
	@echo
	@echo " Generating lzflib package..."
	@echo
	@ar rcs liblzf.a $(OBJECTS)


include $(DEP_FILES)


.PHONY: whatsup
whatsup:
	@echo
	@echo " `date '+ %A, %d %B %Y'`"
	@echo " Generating object files for $(EFILE)..."
	@echo

$(DEP_DIR)/%.d: %.c
	$(SHELL) -ec '$(CC) -M $(CFLAGS) $< \
       | sed '\''s/\($*\)\.o[ :]*/$(OBJDIR)\/\1.o $(@D)\/$(@F) : /g'\'' > $@; \
       [ -s $@ ] || rm -f $@'


.PHONY: tags
tags:
	@echo "Updating tags file..."
	@ctags --recurse=yes --sort=yes *.[ch]


.PHONY: clean
clean:
	rm -rf obj/*.o
	rm -rf .dep/*.d
	rm -rf ../bin/*
	rm -rf core *.core *.a *.so















