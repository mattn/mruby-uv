MRUBY_ROOT = ../..
ifeq ($(OS),Windows_NT)
MRUBY_LIB := $(MRUBY_ROOT)/mrblib/mrblib.o $(MRUBY_ROOT)/lib/ritevm.lib
LDFLAGS =$(MRUBY_LIB) ../libmrb_uv.a  -luv
else
MRUBY_LIB := $(MRUBY_ROOT)/mrblib/mrblib.o $(MRUBY_ROOT)/lib/ritevm.a
LDFLAGS = $(MRUBY_LIB) ../libmrb_uv.a -luv -lpthread -ldl -lrt -lm
endif

INCLUDES = -I$(MRUBY_ROOT)/include -I$(MRUBY_ROOT)/src -I..
CFLAGS = $(INCLUDES) -O3 -g -Wall -Werror-implicit-function-declaration

CC = gcc
LL = gcc
AR = ar

PROGS = timer idle loop tcp-client tcp-server udp-sender udp-reader pipe-client pipe-server

all : $(PROGS)
	@echo done

timer : timer.c
	gcc $(CFLAGS) -o timer timer.c $(LDFLAGS)

idle : idle.c
	gcc $(CFLAGS) -o idle idle.c $(LDFLAGS)

loop : loop.c
	gcc $(CFLAGS) -o loop loop.c $(LDFLAGS)

tcp-client : tcp-client.c
	gcc $(CFLAGS) -o tcp-client tcp-client.c $(LDFLAGS)

tcp-server : tcp-server.c
	gcc $(CFLAGS) -o tcp-server tcp-server.c $(LDFLAGS)

udp-sender : udp-sender.c
	gcc $(CFLAGS) -o udp-sender udp-sender.c $(LDFLAGS)

udp-reader : udp-reader.c
	gcc $(CFLAGS) -o udp-reader udp-reader.c $(LDFLAGS)

pipe-client : pipe-client.c
	gcc $(CFLAGS) -o pipe-client pipe-client.c $(LDFLAGS)

pipe-server : pipe-server.c
	gcc $(CFLAGS) -o pipe-server pipe-server.c $(LDFLAGS)

clean :
	rm -f *.o $(PROGS)
