MRUBY_ROOT = ..
TARGET := ../lib/ritevm
ifeq ($(OS),Windows_NT)
LIB := $(TARGET).lib
else
LIB := $(TARGET).a
endif

INCLUDES = -I$(MRUBY_ROOT)/include -I$(MRUBY_ROOT)/src -I.

CC = gcc
LL = gcc
AR = ar

all : example
	@echo done

example : main.c libmrb_uv.a
	gcc $(INCLUDES) -o example main.c libmrb_uv.a $(LIB) -luv

mrb_uv.o : mrb_uv.c mrb_uv.h
	gcc -c $(INCLUDES) mrb_uv.c

libmrb_uv.a : mrb_uv.o
	$(AR) r libmrb_uv.a mrb_uv.o

clean :
	rm -f *.o example
