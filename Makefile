GEM := mruby-uv
MRUBY_ROOT := ../mruby
MAKEFILE_4_GEM := ../mruby/mrbgems/Makefile4gem

include $(MAKEFILE_4_GEM)

INCLUDE += -I$(MRUBY_ROOT)/include
INCLUDE += -I../libuv/include
CFLAGS  += $(INCLUDE)

GEM_C_FILES := $(wildcard $(SRC_DIR)/*.c)
GEM_OBJECTS := $(patsubst %.c, %.o, $(GEM_C_FILES))

gem-all : $(GEM_OBJECTS) gem-c-files

gem-clean : gem-clean-c-files
