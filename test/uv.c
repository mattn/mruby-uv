#include "mruby.h"
#include "mruby/proc.h"
#include "mruby/uv.h"
#include <signal.h>

static mrb_value raise_signal(mrb_state* mrb, mrb_value self) {
  mrb_int sig;
  (void)self;
  mrb_get_args(mrb, "i", &sig);
  return mrb_fixnum_value(raise(sig));
}

static mrb_int count;
static mrb_value work_cfunc(mrb_state *mrb, mrb_value self) {
  int i;
  mrb_assert(mrb == NULL);
  mrb_assert(mrb_nil_p(self));
  for (i = 0; i < 100; ++i) {
    count += i;
  }
  return self;
}

static mrb_value get_work_result(mrb_state *mrb, mrb_value self) {
  return mrb_fixnum_value(count);
}

#define MRB_UV_SETUP_ARGS()                             \
  do {                                                  \
    int argc = 1;                                       \
    static char proc_title_buf[PATH_MAX];               \
    char const * argv[] = {proc_title_buf, NULL};       \
                                                        \
    strcpy(proc_title_buf, "mrbtest");                  \
    mrb_uv_setup_args(NULL, &argc, (char **)argv, 0);   \
  } while(0)                                            \

#if defined(__clang__) ||                                               \
  defined(__GNUC__) ||                                                  \
  defined(__INTEL_COMPILER) ||                                          \
  defined(__SUNPRO_C)
#define UV_DESTRUCTOR
__attribute__((destructor)) static void setup_args() {
  MRB_UV_SETUP_ARGS();
}
#endif

void mrb_mruby_uv_gem_test(mrb_state* mrb) {
#ifndef UV_DESTRUCTOR
  MRB_UV_SETUP_ARGS();
#endif

  mrb_define_method(mrb, mrb->object_class, "raise_signal", raise_signal, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb->kernel_module, "get_work_result", get_work_result, MRB_ARGS_NONE());
  mrb_define_const(mrb, mrb->object_class, "WorkCFunc", mrb_obj_value(mrb_proc_new_cfunc(mrb, work_cfunc)));
}
