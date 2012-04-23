#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <variable.h>
#include <uv.h>

typedef struct {
  mrb_state* mrb;
  uv_loop_t* loop;
  union {
     uv_idle_t idle;
     uv_timer_t timer;
     uv_loop_t loop;
     uv_handle_t handle;
  } uv;
  mrb_value proc; /* callback   */
} mrb_uv_data;

static mrb_uv_data*
uv_data_alloc(mrb_state* mrb, size_t size)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) malloc(sizeof(mrb_uv_data));
  memset(uvdata, 0, sizeof(mrb_uv_data));
  uvdata->loop = uv_default_loop();
  uvdata->mrb = mrb;
  uvdata->proc = mrb_nil_value();
  return uvdata;
}

static void
uv_data_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_data_type = {
  "uv_data", uv_data_free,
};

/*********************************************************
 * main
 *********************************************************/
static mrb_value
mrb_uv_run(mrb_state *mrb, mrb_value self)
{
  if (uv_run(uv_default_loop()) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static void
_uv_close_cb(uv_handle_t* handle)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) handle->data;
  mrb_yield_argv(uvdata->mrb, uvdata->proc, 0, NULL);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  struct RProc *b = NULL;
  uv_close_cb cb = _uv_close_cb;

  mrb_get_args(mrb, "b", &b);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else cb = NULL;
  uvdata->uv.handle.data = uvdata;

  uv_close(&uvdata->uv.handle, cb);
  return mrb_nil_value();
}

/*********************************************************
 * loop
 *********************************************************/
static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  static struct RClass *c;
  if (c == NULL) {
    mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_loop_t));
    uvdata->uv.loop = *uv_default_loop();
    c = mrb_class_new(mrb, mrb_class_obj_get(mrb, "UV::Loop"));
    mrb_iv_set(mrb, mrb_obj_value(c), mrb_intern(mrb, "data"), mrb_obj_value(
      Data_Wrap_Struct(mrb, (struct RClass*) &self,
      &uv_data_type, (void*) uvdata)));
  }
  return mrb_obj_value(c);
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_loop_t));
  uvdata->uv.loop = *uv_loop_new();
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, (struct RClass*) &self,
    &uv_data_type, (void*) uvdata)));
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (uv_run(&uvdata->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&uvdata->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_run_once(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (uv_run_once(&uvdata->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&uvdata->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_ref(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  uv_ref(&uvdata->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_unref(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  uv_unref(&uvdata->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  uv_loop_delete(&uvdata->uv.loop);
  return mrb_nil_value();
}

/*********************************************************
 * timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  mrb_uv_data* loop_uvdata;
  uv_loop_t* loop;
  mrb_value arg;

  mrb_get_args(mrb, "o", &arg);
  if (!mrb_nil_p(arg)) {
    if (strcmp(mrb_obj_classname(mrb, arg), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
    Data_Get_Struct(mrb, value, &uv_data_type, loop_uvdata);
    loop = &loop_uvdata->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  uvdata = uv_data_alloc(mrb, sizeof(uv_timer_t));
  uvdata->loop = loop;
  if (uv_timer_init(loop, &uvdata->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, (struct RClass*) &self,
    &uv_data_type, (void*) uvdata)));
  return self;
}

static void
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
  mrb_value arg1, arg2;
  uv_timer_cb cb = _uv_timer_cb;

  mrb_get_args(mrb, "bii", &b, &arg1, &arg2);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else cb = NULL;
  uvdata->uv.handle.data = uvdata;

  if (uv_timer_start(&uvdata->uv.timer, cb,
      mrb_fixnum(arg1), mrb_fixnum(arg2)) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (uv_timer_stop(&uvdata->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  mrb_uv_data* loop_uvdata;
  uv_loop_t* loop;
  mrb_value arg;

  mrb_get_args(mrb, "o", &arg);
  if (!mrb_nil_p(arg)) {
    if (strcmp(mrb_obj_classname(mrb, arg), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
    Data_Get_Struct(mrb, value, &uv_data_type, loop_uvdata);
    loop = &loop_uvdata->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  uvdata = uv_data_alloc(mrb, sizeof(uv_idle_t));
  uvdata->loop = loop;
  if (uv_idle_init(loop, &uvdata->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, (struct RClass*) &self,
    &uv_data_type, (void*) uvdata)));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle, int status)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) idle->data;
  mrb_yield(uvdata->mrb, uvdata->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  struct RProc *b;
  uv_idle_cb cb = _uv_idle_cb;

  mrb_get_args(mrb, "b", &b);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else cb = NULL;
  uvdata->uv.handle.data = uvdata;

  if (uv_idle_start(&uvdata->uv.idle, cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (uv_idle_stop(&uvdata->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

void
mrb_uv_init(mrb_state* mrb) {
  struct RClass *uv, *uv_loop, *uv_timer, *uv_idle;

  uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, uv, "run", mrb_uv_run, ARGS_REQ(1));
  mrb_define_class_method(mrb, uv, "default_loop", mrb_uv_default_loop, ARGS_REQ(1));

  uv_loop = mrb_define_class_under(mrb, uv, "Loop", mrb->object_class);
  mrb_define_method(mrb, uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, uv_loop, "run", mrb_uv_loop_run, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "run_once", mrb_uv_loop_run_once, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "ref", mrb_uv_loop_ref, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "unref", mrb_uv_loop_unref, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "delete", mrb_uv_loop_delete, ARGS_REQ(1));

  uv_timer = mrb_define_class_under(mrb, uv, "Timer", mrb->object_class);
  mrb_define_method(mrb, uv_timer, "initialize", mrb_uv_timer_init, ARGS_OPT(1));
  mrb_define_method(mrb, uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, uv_timer, "stop", mrb_uv_timer_stop, ARGS_REQ(1));
  mrb_define_method(mrb, uv_timer, "close", mrb_uv_close, ARGS_OPT(1));

  uv_idle = mrb_define_class_under(mrb, uv, "Idle", mrb->object_class);
  mrb_define_method(mrb, uv_idle, "initialize", mrb_uv_idle_init, ARGS_OPT(1));
  mrb_define_method(mrb, uv_idle, "start", mrb_uv_idle_start, ARGS_REQ(2));
  mrb_define_method(mrb, uv_idle, "stop", mrb_uv_idle_stop, ARGS_REQ(1));
  mrb_define_method(mrb, uv_idle, "close", mrb_uv_close, ARGS_OPT(1));
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
