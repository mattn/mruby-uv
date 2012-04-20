#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <variable.h>
#include <uv.h>

typedef struct {
  mrb_state* mrb;
  mrb_value proc; /* callback   */
  void* data;     /* uv pointer */
} mrb_uv_data;

static void
uv_handle_free(mrb_state *mrb, void *p)
{
  uv_close((uv_handle_t*) ((mrb_uv_data*)p)->data, NULL);
  free(((mrb_uv_data*)p)->data);
}

static const struct mrb_data_type uv_handle_data_type = {
  "uv_handle", uv_handle_free,
};

static mrb_value
mrb_uv_run(mrb_state *mrb, mrb_value self)
{
  if (uv_run(uv_default_loop()) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) malloc(sizeof(mrb_uv_data));
  uvdata->mrb = mrb;
  uvdata->data = malloc(sizeof(uv_timer_t));
  uvdata->proc = mrb_nil_value();
  if (uv_timer_init(uv_default_loop(), (uv_timer_t*) uvdata->data) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, (struct RClass*) &self,
    &uv_handle_data_type, (void*) uvdata)));
  return self;
}

void
_uv_timer_cb(uv_timer_t* timer, int status)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) timer->data;
  mrb_yield(uvdata->mrb, uvdata->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  struct RProc *b;
  mrb_value argc, *argv;
  int nargs;

  mrb_get_args(mrb, "b*", &b, &argv, &argc);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_handle_data_type, uvdata);
  uvdata->proc = mrb_obj_value(b);
  ((uv_timer_t*) uvdata->data)->data = uvdata;

  if (uv_timer_start((uv_timer_t*) uvdata->data, _uv_timer_cb,
      mrb_fixnum(argv[0]), mrb_fixnum(argv[1])) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  struct RProc *b;
  mrb_value argc, *argv;
  int nargs;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_handle_data_type, uvdata);
  if (uv_timer_stop((uv_timer_t*) uvdata->data) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

void
mrb_uv_init(mrb_state* mrb) {
  struct RClass *uv, *uv_timer;

  uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, uv, "run", mrb_uv_run, ARGS_REQ(1));

  uv_timer = mrb_define_class_under(mrb, uv, "Timer", mrb_class_obj_get(mrb, "Object"));
  mrb_define_method(mrb, uv_timer, "initialize", mrb_uv_timer_init, ARGS_ANY());
  mrb_define_method(mrb, uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, uv_timer, "stop", mrb_uv_timer_stop, ARGS_REQ(1));
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
