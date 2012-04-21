MRUBY_ROOT = ..
TARGET := ../lib/ritevm
ifeq ($(OS),Windows_NT)
MRUBY_LIB := $(TARGET).lib
LIB = $(MRUBY_LIB) -luv
else
MRUBY_LIB := $(TARGET).a
LIB = $(MRUBY_LIB) -luv -lpthread -ldl -lrt -lm
endif

INCLUDES = -I$(MRUBY_ROOT)/include -I$(MRUBY_ROOT)/src -I.
CFLAGS = $(INCLUDES) -O3 -g -Wall -Werror-implicit-function-declaration

CC = gcc
LL = gcc
AR = ar

all : timer idle loop
	@echo done

timer : timer.c libmrb_uv.a
	gcc $(CFLAGS) -o timer timer.c libmrb_uv.a $(LIB)

idle : idle.c libmrb_uv.a
	gcc $(CFLAGS) -o idle idle.c libmrb_uv.a $(LIB)

loop : loop.c libmrb_uv.a
	gcc $(CFLAGS) -o loop loop.c libmrb_uv.a $(LIB)

mrb_uv.o : mrb_uv.c mrb_uv.h
	gcc -c $(CFLAGS) mrb_uv.c

libmrb_uv.a : mrb_uv.o
	$(AR) r libmrb_uv.a mrb_uv.o

clean :
	rm -f *.o timer idle loop
