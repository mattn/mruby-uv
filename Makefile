GEM := mruby-uv

include $(MAKEFILE_4_GEM)

CFLAGS += -I$(MRUBY_ROOT)/include
LDFLAGS += -luv
MRUBY_CFLAGS += -I$(MRUBY_ROOT)/include
MRUBY_LDFLAGS += -luv

GEM_C_FILES := $(wildcard $(SRC_DIR)/*.c)
GEM_OBJECTS := $(patsubst %.c, %.o, $(GEM_C_FILES))

gem-all : $(GEM_OBJECTS) gem-c-files

gem-clean : gem-clean-c-files
