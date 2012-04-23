MRUBY_ROOT = ..

INCLUDES = -I$(MRUBY_ROOT)/include -I$(MRUBY_ROOT)/src -I.
CFLAGS = $(INCLUDES) -O3 -g -Wall -Werror-implicit-function-declaration

CC = gcc
LL = gcc
AR = ar

all : libmrb_uv.a
	@echo done

mrb_uv.o : mrb_uv.c mrb_uv.h
	gcc -c $(CFLAGS) mrb_uv.c

libmrb_uv.a : mrb_uv.o
	$(AR) r libmrb_uv.a mrb_uv.o

clean :
	rm -f *.o libmrb_uv.a
