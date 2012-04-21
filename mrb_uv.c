#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <variable.h>
#include <uv.h>

typedef struct {
  mrb_state* mrb;
  void* pv;      /* uv pointer */
  mrb_value proc; /* callback   */
} mrb_uv_data;

static mrb_uv_data*
uv_data_alloc(mrb_state* mrb, size_t size)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) mrb_malloc(mrb, sizeof(mrb_uv_data));
  memset(uvdata, 0, sizeof(mrb_uv_data));
  uvdata->mrb = mrb;
  uvdata->pv = mrb_malloc(mrb, size + 9);
  memset(uvdata->pv, 0, size);
  uvdata->proc = mrb_nil_value();
  return uvdata;
}

static void
uv_data_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, ((mrb_uv_data*)p)->pv);
  mrb_free(mrb, p);
}

static const struct mrb_data_type uv_data_type = {
  "uv_handle", uv_data_free,
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
  ((uv_handle_t*) uvdata->pv)->data = uvdata;

  uv_close((uv_handle_t *) uvdata->pv, cb);
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
    uvdata->pv = (void*) uv_default_loop();
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
  struct RClass *c = mrb_class_new(mrb, mrb_class_obj_get(mrb, "UV::Loop"));
  mrb_iv_set(mrb, mrb_obj_value(c), mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, (struct RClass*) &self,
    &uv_data_type, (void*) uvdata)));
  return mrb_obj_value(c);
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (uv_run((uv_loop_t*) uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error((uv_loop_t*) uvdata->pv)));
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
  if (uv_run_once((uv_loop_t*) uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error((uv_loop_t*) uvdata->pv)));
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
  uv_ref((uv_loop_t*) uvdata->pv);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_unref(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  uv_unref((uv_loop_t*) uvdata->pv);
  return mrb_nil_value();
}

/*********************************************************
 * timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_timer_t));
  if (uv_timer_init(uv_default_loop(), (uv_timer_t*) uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
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
  ((uv_handle_t*) uvdata->pv)->data = uvdata;

  if (uv_timer_start((uv_timer_t*) uvdata->pv, cb,
      mrb_fixnum(arg1), mrb_fixnum(arg2)) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
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
  if (uv_timer_stop((uv_timer_t*) uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

/*********************************************************
 * idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_idle_t));
  if (uv_idle_init(uv_default_loop(), uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
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
  ((uv_idle_t*) uvdata->pv)->data = uvdata;

  if (uv_idle_start((uv_idle_t*) uvdata->pv, cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
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
  if (uv_idle_stop((uv_idle_t*) uvdata->pv) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

void
mrb_uv_init(mrb_state* mrb) {
  struct RClass *uv, *uv_loop, *uv_timer, *uv_idle;

  uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, uv, "run", mrb_uv_run, ARGS_REQ(1));
  mrb_define_class_method(mrb, uv, "default_loop", mrb_uv_default_loop, ARGS_REQ(1));

  uv_loop = mrb_define_class_under(mrb, uv, "Loop", mrb_class_obj_get(mrb, "Object"));
  mrb_define_method(mrb, uv_loop, "initialize", mrb_uv_loop_init, ARGS_ANY());
  mrb_define_method(mrb, uv_loop, "run", mrb_uv_loop_run, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "run_once", mrb_uv_loop_run_once, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "ref", mrb_uv_loop_ref, ARGS_REQ(1));
  mrb_define_method(mrb, uv_loop, "unref", mrb_uv_loop_unref, ARGS_REQ(1));

  uv_timer = mrb_define_class_under(mrb, uv, "Timer", mrb_class_obj_get(mrb, "Object"));
  mrb_define_method(mrb, uv_timer, "initialize", mrb_uv_timer_init, ARGS_ANY());
  mrb_define_method(mrb, uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, uv_timer, "stop", mrb_uv_timer_stop, ARGS_REQ(1));
  mrb_define_method(mrb, uv_timer, "close", mrb_uv_close, ARGS_REQ(1));

  uv_idle = mrb_define_class_under(mrb, uv, "Idle", mrb_class_obj_get(mrb, "Object"));
  mrb_define_method(mrb, uv_idle, "initialize", mrb_uv_idle_init, ARGS_ANY());
  mrb_define_method(mrb, uv_idle, "start", mrb_uv_idle_start, ARGS_REQ(2));
  mrb_define_method(mrb, uv_idle, "stop", mrb_uv_idle_stop, ARGS_REQ(1));
  mrb_define_method(mrb, uv_idle, "close", mrb_uv_close, ARGS_REQ(1));
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
