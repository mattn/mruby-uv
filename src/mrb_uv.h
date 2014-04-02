#ifndef MRB_UV_H
#define MRB_UV_H

#include <uv.h>

#ifndef _MSC_VER
#include <unistd.h>
#else
#define PATH_MAX MAX_PATH
#endif

#include <mruby.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/class.h>
#include <mruby/variable.h>

#ifndef MRUBY_VERSION
#define mrb_module_get mrb_class_get
#endif

extern const struct mrb_data_type mrb_uv_ip4addr_type;
extern const struct mrb_data_type mrb_uv_ip6addr_type;
extern const struct mrb_data_type mrb_uv_ip4addr_nofree_type;
extern const struct mrb_data_type mrb_uv_ip6addr_nofree_type;
extern const struct mrb_data_type mrb_uv_loop_type;

void mrb_mruby_uv_gem_init_handle(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_thread(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_dl(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_fs(mrb_state *mrb, struct RClass *UV);

mrb_value mrb_uv_data_get(mrb_state *mrb, mrb_value self);
mrb_value mrb_uv_data_set(mrb_state *mrb, mrb_value self);

void* mrb_uv_get_ptr(mrb_state*, mrb_value, struct mrb_data_type const*);

mrb_value mrb_uv_gc_table_get(mrb_state *mrb);
void mrb_uv_gc_table_clean(mrb_state *mrb);
void mrb_uv_gc_protect(mrb_state *mrb, mrb_value v);

#endif
