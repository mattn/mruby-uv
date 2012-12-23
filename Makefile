GEM := mruby-uv

include $(MAKEFILE_4_GEM)

CFLAGS += -I$(MRUBY_ROOT)/include
MRUBY_CFLAGS += -I$(MRUBY_ROOT)/include
ifeq ($(OS),Windows_NT)
MRUBY_LIBS += -luv -lws2_32 -liphlpapi -lpsapi
else
MRUBY_LIBS += -luv -lrt -lm
endif

GEM_C_FILES := $(wildcard $(SRC_DIR)/*.c)
GEM_OBJECTS := $(patsubst %.c, %.o, $(GEM_C_FILES))

gem-all : $(GEM_OBJECTS) gem-c-files

gem-clean : gem-clean-c-files
