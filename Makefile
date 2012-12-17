GEM := mruby-uv

include $(MAKEFILE_4_GEM)

INCLUDE += -I$(MRUBY_ROOT)/include
INCLUDE += -Ilibuv/include
CFLAGS  += $(INCLUDE) -g -O3

GEM_C_FILES := $(wildcard $(SRC_DIR)/*.c)
GEM_OBJECTS := $(patsubst %.c, %.o, $(GEM_C_FILES))

gem-all : $(GEM_OBJECTS) gem-c-files

gem-clean : gem-clean-c-files
