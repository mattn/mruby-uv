#ifndef MRUBY_UV_H
#define MRUBY_UV_H

#ifdef __cplusplus
extern "C" {
#endif

mrb_value mrb_uv_dlopen(mrb_state *mrb, char const *name);
void* mrb_uv_dlsym(mrb_state *mrb, mrb_value dl, char const *name);
void mrb_uv_dlclose(mrb_state *mrb, mrb_value dl);

#ifdef __cplusplus
}
#endif

#endif
