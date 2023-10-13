TARGET=libtls.$(LIB_EXTENSION)
SRCS=$(wildcard src/*.c)
SOBJ=$(SRCS:.c=.$(LIB_EXTENSION))
SUBMOD:=$(filter-out src/$(TARGET),$(SOBJ))
INSTALL?=install

ifdef LIBTLS_COVERAGE
COVFLAGS=--coverage
endif


.PHONY: all install

all: $(SOBJ)

%.o: %.c
	$(CC) $(CFLAGS) $(WARNINGS) $(COVFLAGS) $(CPPFLAGS) -o $@ -c $<

%.$(LIB_EXTENSION): %.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(PLATFORM_LDFLAGS) $(COVFLAGS)

install:
	$(INSTALL) -d $(INST_LIBDIR)
	$(INSTALL) src/$(TARGET) $(INST_LIBDIR)
	$(INSTALL) -d $(INST_LIBDIR)/libtls
	$(INSTALL) $(SUBMOD) $(INST_LIBDIR)/libtls/
	rm -f ./src/*.o ./src/*.so ./src/*.gcda

