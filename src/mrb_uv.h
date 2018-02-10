#ifndef MRB_UV_H
#define MRB_UV_H

#include <uv.h>

#ifndef _MSC_VER
#include <unistd.h>
#include <limits.h>
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

#include <mruby/uv.h>

#ifndef MRUBY_VERSION
#define mrb_module_get mrb_class_get
#define mrb_uv_args_int int
#else
#define mrb_uv_args_int mrb_int
#endif

#ifdef ARY_SET_LEN
#define RARRAY_SET_LEN(ary, len) do {\
  struct RArray *a = mrb_ary_ptr(ary);\
  ARY_SET_LEN(a, len);\
} while(0)
#else
#define RARRAY_SET_LEN(ary, len) do {\
  RARRAY_LEN(ary) = len;\
} while (0)
#endif
#ifndef ARY_PTR
#define ARY_PTR(a) (a->ptr)
#endif

#define symbol_value_lit(mrb, lit) (mrb_symbol_value(mrb_intern_lit(mrb, lit)))

extern const struct mrb_data_type mrb_uv_ip4addr_type;
extern const struct mrb_data_type mrb_uv_ip6addr_type;
extern const struct mrb_data_type mrb_uv_ip4addr_nofree_type;
extern const struct mrb_data_type mrb_uv_ip6addr_nofree_type;
extern const struct mrb_data_type mrb_uv_loop_type;

void mrb_mruby_uv_gem_init_handle(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_thread(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_dl(mrb_state *mrb, struct RClass *UV);
void mrb_mruby_uv_gem_init_fs(mrb_state *mrb, struct RClass *UV);

mrb_value mrb_uv_create_stat(mrb_state*, uv_stat_t const*);

mrb_value mrb_uv_data_get(mrb_state *mrb, mrb_value self);
mrb_value mrb_uv_data_set(mrb_state *mrb, mrb_value self);

void* mrb_uv_get_ptr(mrb_state*, mrb_value, struct mrb_data_type const*);
uv_file mrb_uv_to_fd(mrb_state *mrb, mrb_value v);

mrb_value mrb_uv_gc_table_get(mrb_state *mrb);
void mrb_uv_gc_table_clean(mrb_state *mrb, uv_loop_t *l);
void mrb_uv_gc_protect(mrb_state *mrb, mrb_value v);

struct mrb_uv_req_t {
  mrb_state *mrb;
  mrb_value instance, block;
  mrb_bool is_used:1;
  union uv_any_req req;
};

void mrb_uv_req_clear(mrb_uv_req_t *req);
mrb_uv_req_t *mrb_uv_req_current(mrb_state *mrb, mrb_value blk, mrb_value *result);
void mrb_uv_req_yield(mrb_uv_req_t *req, mrb_int argc, mrb_value const *argv);
void mrb_uv_req_set_buf(mrb_uv_req_t *req, uv_buf_t *buf, mrb_value str);

typedef struct {
  mrb_state* mrb;
  mrb_value instance, block;
  uv_handle_t handle;
} mrb_uv_handle;

extern const struct mrb_data_type mrb_uv_handle_type;

uv_os_sock_t mrb_uv_to_socket(mrb_state *mrb, mrb_value v);

mrb_value mrb_uv_from_uint64(mrb_state *mrb, uint64_t v);

#ifdef _WIN32
#  include <io.h>
#  ifndef S_IRUSR
#    define S_IRUSR _S_IREAD
#  endif
#  ifndef S_IWUSR
#    define S_IWUSR _S_IWRITE
#  endif
#  ifndef S_IXUSR
#    define S_IXUSR _S_IEXEC
#  endif
#endif

#define MRB_UV_CHECK_VERSION(maj, min, pat)                             \
  ((UV_VERSION_MAJOR >  (maj)) ||                                       \
   (UV_VERSION_MAJOR >= (maj) && UV_VERSION_MINOR >  (min)) ||          \
   (UV_VERSION_MAJOR >= (maj) && UV_VERSION_MINOR >= (min) && UV_VERSION_PATCH >= (pat))) \

uv_loop_t* mrb_uv_current_loop(mrb_state *mrb);
mrb_value mrb_uv_current_loop_obj(mrb_state *mrb);

void mrb_uv_close_handle_belongs_to_vm(uv_handle_t * h, void *arg);

mrb_value mrb_uv_create_error(mrb_state *mrb, int err);
mrb_value mrb_uv_create_status(mrb_state *mrb, int status);

#endif
