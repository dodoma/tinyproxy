APP = tinyproxy
CC = gcc
CFLAGS = -g

LIBS = -lpthread

all: $(APP)

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
DEPEND	= .depend

$(DEPEND): $(SOURCES)
	@$(CC) $(CFLAGS) $(INCS) -MM $^ > $@

include $(DEPEND)
%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -o $@ -c $<

tinyproxy: tproxy.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
