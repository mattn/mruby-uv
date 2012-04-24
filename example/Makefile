MRUBY_ROOT = ../..
TARGET := $(MRUBY_ROOT)/lib/ritevm
ifeq ($(OS),Windows_NT)
MRUBY_LIB := $(TARGET).lib
LIB = $(MRUBY_LIB) -luv
else
MRUBY_LIB := $(TARGET).a
LIB = $(MRUBY_LIB) -luv -lpthread -ldl -lrt -lm
endif

INCLUDES = -I$(MRUBY_ROOT)/include -I$(MRUBY_ROOT)/src -I..
CFLAGS = $(INCLUDES) -O3 -g -Wall -Werror-implicit-function-declaration

CC = gcc
LL = gcc
AR = ar

all : timer idle loop tcp-client tcp-server
	@echo done

timer : timer.c
	gcc $(CFLAGS) -o timer timer.c ../libmrb_uv.a $(LIB)

idle : idle.c
	gcc $(CFLAGS) -o idle idle.c ../libmrb_uv.a $(LIB)

loop : loop.c
	gcc $(CFLAGS) -o loop loop.c ../libmrb_uv.a $(LIB)

tcp-client : tcp-client.c
	gcc $(CFLAGS) -o tcp-client tcp-client.c ../libmrb_uv.a $(LIB)

tcp-server : tcp-server.c
	gcc $(CFLAGS) -o tcp-server tcp-server.c ../libmrb_uv.a $(LIB)

clean :
	rm -f *.o timer idle loop tcp-client tcp-server
