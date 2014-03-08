#include "mruby.h"
#include <signal.h>

static mrb_value raise_signal(mrb_state* mrb, mrb_value self) {
  (void)self;
  mrb_int sig;
  mrb_get_args(mrb, "i", &sig);
  return mrb_fixnum_value(raise(sig));
}

void mrb_mruby_uv_gem_test(mrb_state* mrb) {
  mrb_define_method(mrb, mrb->object_class, "raise_signal", raise_signal, MRB_ARGS_REQ(1));
}
