#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <compile.h>
#include <variable.h>
#include <uv.h>

typedef struct {
  mrb_state* mrb;
  uv_loop_t* loop;
  union {
     uv_tcp_t tcp;
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

static void
uv_ip4_addr_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_ip4_addr_type = {
  "uv_ip4addr", uv_ip4_addr_free,
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
  uv_close_cb close_cb = _uv_close_cb;

  mrb_get_args(mrb, "b", &b);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else close_cb = NULL;

  uv_close(&uvdata->uv.handle, close_cb);
  return mrb_nil_value();
}

/*********************************************************
 * loop
 *********************************************************/
static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  static int initialized = FALSE;
  if (!initialized) {
    initialized = TRUE;
    mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_loop_t));
    uvdata->uv.loop = *uv_default_loop();
    c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::Loop"));
    mrb_iv_set(mrb, c, mrb_intern(mrb, "data"), mrb_obj_value(
      Data_Wrap_Struct(mrb, mrb->object_class,
      &uv_data_type, (void*) uvdata)));
  }
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_data* uvdata = uv_data_alloc(mrb, sizeof(uv_loop_t));
  uvdata->uv.loop = *uv_loop_new();
  uvdata->uv.loop.data = uvdata;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
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
  uvdata->uv.timer.data = uvdata;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
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
  uv_timer_cb timer_cb = _uv_timer_cb;

  mrb_get_args(mrb, "bii", &b, &arg1, &arg2);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else timer_cb = NULL;

  if (uv_timer_start(&uvdata->uv.timer, timer_cb,
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
  uvdata->uv.idle.data = uvdata;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
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
  uv_idle_cb idle_cb = _uv_idle_cb;

  mrb_get_args(mrb, "b", &b);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else idle_cb = NULL;

  if (uv_idle_start(&uvdata->uv.idle, idle_cb) != 0) {
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

/*********************************************************
 * tcp
 *********************************************************/
static mrb_value
mrb_uv_ip4_addr(mrb_state *mrb, mrb_value self)
{
  int argc;
  mrb_value *argv;
  mrb_get_args(mrb, "*", &argv, &argc);
  return mrb_class_new_instance(mrb, argc, argv, mrb_class_get(mrb, "UV::Ip4Addr"));
}

static mrb_value
mrb_uv_ip4_addr_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg1, arg2;
  struct sockaddr_in vaddr;
  struct sockaddr_in *addr;
  mrb_get_args(mrb, "oi", &arg1, &arg2);
  vaddr = uv_ip4_addr((const char*) RSTRING_PTR(arg1), mrb_fixnum(arg2));
  addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
  memcpy(addr, &vaddr, sizeof(vaddr));
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_ip4_addr_type, (void*) addr)));
  return self;
}

static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
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

  uvdata = uv_data_alloc(mrb, sizeof(uv_tcp_t));
  uvdata->loop = loop;
  if (uv_tcp_init(loop, &uvdata->uv.tcp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  uvdata->uv.tcp.data = uvdata;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_data_type, (void*) uvdata)));
  return self;
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) req->handle->data;
  mrb_yield(uvdata->mrb, uvdata->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value value1, value2;
  mrb_uv_data* uvdata;
  struct RProc *b = NULL;
  int argc;
  mrb_value *argv;
  uv_connect_cb connect_cb = _uv_connect_cb;
  static uv_connect_t req;
  struct sockaddr_in* addr = NULL;

  mrb_get_args(mrb, "b*", &b, &argv, &argc);
  if (mrb_nil_p(argv[0]) || strcmp(mrb_obj_classname(mrb, argv[0]), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value1 = mrb_iv_get(mrb, argv[0], mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value1, &uv_ip4_addr_type, addr);

  value2 = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value2, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else connect_cb = NULL;

  if (uv_tcp_connect(&req, &uvdata->uv.tcp, *addr, connect_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

static uv_buf_t
_uv_alloc_cb(uv_handle_t* handle, size_t suggested_size)
{
  return uv_buf_init(malloc(suggested_size), suggested_size);
}

static void
_uv_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
  mrb_uv_data* uvdata = (mrb_uv_data*) stream->data;
  mrb_yield(uvdata->mrb, uvdata->proc, mrb_str_new(uvdata->mrb, buf.base, nread));
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_data* uvdata;
  struct RProc *b;
  uv_read_cb read_cb = _uv_read_cb;

  mrb_get_args(mrb, "b", &b);
  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_data_type, uvdata);
  if (b) uvdata->proc = mrb_obj_value(b);
  else read_cb = NULL;

  if (uv_read_start((uv_stream_t*) &uvdata->uv.tcp, _uv_alloc_cb, read_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uvdata->loop)));
  }
  return mrb_nil_value();
}

void
mrb_uv_init(mrb_state* mrb) {
  struct RClass *_uv, *_uv_loop, *_uv_timer, *_uv_idle, *_uv_tcp, *_uv_ip4_addr;

  _uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, _uv, "run", mrb_uv_run, ARGS_NONE());
  mrb_define_class_method(mrb, _uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_class_method(mrb, _uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));

  _uv_loop = mrb_define_class_under(mrb, _uv, "Loop", mrb->object_class);
  mrb_define_method(mrb, _uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, _uv_loop, "run", mrb_uv_loop_run, ARGS_NONE());
  mrb_define_method(mrb, _uv_loop, "run_once", mrb_uv_loop_run_once, ARGS_NONE());
  mrb_define_method(mrb, _uv_loop, "ref", mrb_uv_loop_ref, ARGS_NONE());
  mrb_define_method(mrb, _uv_loop, "unref", mrb_uv_loop_unref, ARGS_NONE());
  mrb_define_method(mrb, _uv_loop, "delete", mrb_uv_loop_delete, ARGS_NONE());

  _uv_timer = mrb_define_class_under(mrb, _uv, "Timer", mrb->object_class);
  mrb_define_method(mrb, _uv_timer, "initialize", mrb_uv_timer_init, ARGS_OPT(1));
  mrb_define_method(mrb, _uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, _uv_timer, "stop", mrb_uv_timer_stop, ARGS_NONE());
  mrb_define_method(mrb, _uv_timer, "close", mrb_uv_close, ARGS_OPT(1));

  _uv_idle = mrb_define_class_under(mrb, _uv, "Idle", mrb->object_class);
  mrb_define_method(mrb, _uv_idle, "initialize", mrb_uv_idle_init, ARGS_OPT(1));
  mrb_define_method(mrb, _uv_idle, "start", mrb_uv_idle_start, ARGS_REQ(1));
  mrb_define_method(mrb, _uv_idle, "stop", mrb_uv_idle_stop, ARGS_NONE());
  mrb_define_method(mrb, _uv_idle, "close", mrb_uv_close, ARGS_OPT(1));

  _uv_ip4_addr = mrb_define_class_under(mrb, _uv, "Ip4Addr", mrb->object_class);
  mrb_define_method(mrb, _uv_ip4_addr, "initialize", mrb_uv_ip4_addr_init, ARGS_REQ(2));

  _uv_tcp = mrb_define_class_under(mrb, _uv, "TCP", mrb->object_class);
  mrb_define_method(mrb, _uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _uv_tcp, "connect", mrb_uv_tcp_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _uv_tcp, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _uv_tcp, "close", mrb_uv_close, ARGS_OPT(1));
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
