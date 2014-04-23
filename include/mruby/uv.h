#ifndef MRUBY_UV_H
#define MRUBY_UV_H

#include "mruby.h"

#ifdef __cplusplus
extern "C" {
#endif

mrb_value mrb_uv_dlopen(mrb_state *mrb, char const *name);
void* mrb_uv_dlsym(mrb_state *mrb, mrb_value dl, char const *name);
void mrb_uv_dlclose(mrb_state *mrb, mrb_value dl);

#define E_UV_ERROR mrb_class_get(mrb, "UVError")
void mrb_uv_check_error(mrb_state*, int);

char** mrb_uv_setup_args(mrb_state *mrb, int *argc, char **argv, mrb_bool set_global);

#ifdef __cplusplus
}
#endif

#endif
