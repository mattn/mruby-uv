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

PROGS = runner

all : $(PROGS)
	@echo done

runner : runner.c
	gcc $(CFLAGS) -o runner runner.c $(LDFLAGS)

clean :
	rm -f *.o $(PROGS)
