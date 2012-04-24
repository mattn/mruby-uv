#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <mruby/variable.h>
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
  mrb_value proc; /* callback */
} mrb_uv_context;

static mrb_uv_context*
uv_context_alloc(mrb_state* mrb, size_t size)
{
  mrb_uv_context* context = (mrb_uv_context*) malloc(sizeof(mrb_uv_context));
  memset(context, 0, sizeof(mrb_uv_context));
  context->loop = uv_default_loop();
  context->mrb = mrb;
  context->proc = mrb_nil_value();
  return context;
}

static void
uv_context_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_context_type = {
  "uv_context", uv_context_free,
};

static void
uv_ip4addr_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_ip4addr_type = {
  "uv_ip4addr", uv_ip4addr_free,
};

static struct RClass *_class_uv;
static struct RClass *_class_uv_loop;
static struct RClass *_class_uv_timer;
static struct RClass *_class_uv_idle;
static struct RClass *_class_uv_tcp;
static struct RClass *_class_uv_ip4addr;

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
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_yield_argv(context->mrb, context->proc, 0, NULL);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b = NULL;
  uv_close_cb close_cb = _uv_close_cb;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "b", &b);
  if (b) context->proc = mrb_obj_value(b);
  else close_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "close_cb"), context->proc);

  uv_close(&context->uv.handle, close_cb);
  return mrb_nil_value();
}

/*********************************************************
 * loop
 *********************************************************/
static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_context* context;

  context = uv_context_alloc(mrb, sizeof(uv_loop_t));
  context->uv.loop = *uv_default_loop();
#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::Loop"));
#else
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_loop);
#endif
  mrb_iv_set(mrb, c, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_context* context = uv_context_alloc(mrb, sizeof(uv_loop_t));
  context->uv.loop = *uv_loop_new();
  context->uv.loop.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  if (uv_run(&context->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&context->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_run_once(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  if (uv_run_once(&context->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&context->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_ref(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  uv_ref(&context->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_unref(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  uv_unref(&context->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  uv_loop_delete(&context->uv.loop);
  return mrb_nil_value();
}

/*********************************************************
 * timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value;
  mrb_uv_context* context;
  mrb_uv_context* loop_uvdata;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg);
  if (!mrb_nil_p(arg)) {
    if (strcmp(mrb_obj_classname(mrb, arg), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
    Data_Get_Struct(mrb, value, &uv_context_type, loop_uvdata);

    loop = &loop_uvdata->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, sizeof(uv_timer_t));
  context->loop = loop;
  if (uv_timer_init(loop, &context->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.timer.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_timer_cb(uv_timer_t* timer, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) timer->data;
  mrb_yield(context->mrb, context->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  mrb_value arg1, arg2;
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b;
  uv_timer_cb timer_cb = _uv_timer_cb;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "bii", &b, &arg1, &arg2);
  if (b) context->proc = mrb_obj_value(b);
  else timer_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "timer_cb"), context->proc);

  if (uv_timer_start(&context->uv.timer, timer_cb,
      mrb_fixnum(arg1), mrb_fixnum(arg2)) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  if (uv_timer_stop(&context->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value;
  mrb_uv_context* context;
  mrb_uv_context* loop_uvdata;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg);
  if (!mrb_nil_p(arg)) {
    if (strcmp(mrb_obj_classname(mrb, arg), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
    Data_Get_Struct(mrb, value, &uv_context_type, loop_uvdata);
    loop = &loop_uvdata->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, sizeof(uv_idle_t));
  context->loop = loop;
  if (uv_idle_init(loop, &context->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.idle.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) idle->data;
  mrb_yield(context->mrb, context->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b;
  uv_idle_cb idle_cb = _uv_idle_cb;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "b", &b);
  if (b) context->proc = mrb_obj_value(b);
  else idle_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "idle_cb"), context->proc);

  if (uv_idle_start(&context->uv.idle, idle_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  if (uv_idle_stop(&context->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
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
#if 0
  return mrb_class_new_instance(mrb, argc, argv, mrb_class_get(mrb, "UV::Ip4Addr"));
#else
  return mrb_class_new_instance(mrb, argc, argv, _class_uv_ip4addr);
#endif
}

static mrb_value
mrb_uv_ip4addr_init(mrb_state *mrb, mrb_value self)
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
    &uv_ip4addr_type, (void*) addr)));
  return self;
}

static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value;
  mrb_uv_context* context;
  mrb_uv_context* loop_uvdata;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg);
  if (!mrb_nil_p(arg)) {
    if (strcmp(mrb_obj_classname(mrb, arg), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
    Data_Get_Struct(mrb, value, &uv_context_type, loop_uvdata);
    loop = &loop_uvdata->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, sizeof(uv_tcp_t));
  context->loop = loop;
  if (uv_tcp_init(loop, &context->uv.tcp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.tcp.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_yield(context->mrb, context->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self)
{
  int argc;
  mrb_value *argv;
  mrb_value value1, value2;
  mrb_uv_context* context;
  struct RProc *b = NULL;
  uv_connect_cb connect_cb = _uv_connect_cb;
  static uv_connect_t req;
  struct sockaddr_in* addr = NULL;

  value1 = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value1, &uv_context_type, context);

  mrb_get_args(mrb, "b*", &b, &argv, &argc);
  if (mrb_nil_p(argv[0]) || strcmp(mrb_obj_classname(mrb, argv[0]), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value2 = mrb_iv_get(mrb, argv[0], mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value2, &uv_ip4addr_type, addr);

  if (b) context->proc = mrb_obj_value(b);
  else connect_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), context->proc);

  if (uv_tcp_connect(&req, &context->uv.tcp, *addr, connect_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
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
  mrb_uv_context* context = (mrb_uv_context*) stream->data;
  mrb_yield(context->mrb, context->proc, mrb_str_new(context->mrb, buf.base, nread));
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b;
  uv_read_cb read_cb = _uv_read_cb;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "b", &b);
  if (b) context->proc = mrb_obj_value(b);
  else read_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "read_cb"), context->proc);

  if (uv_read_start((uv_stream_t*) &context->uv.tcp, _uv_alloc_cb, read_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_write_cb(uv_write_t* req, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_yield(context->mrb, context->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b;
  uv_write_cb write_cb = _uv_write_cb;
  static uv_write_t req = {0};
  static uv_buf_t buf;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "bs", &b, &arg);
  if (b) context->proc = mrb_obj_value(b);
  else write_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "write_cb"), context->proc);

  buf = uv_buf_init((char*) RSTRING_PTR(arg), RSTRING_CAPA(arg));
  if (uv_write(&req, (uv_stream_t*) &context->uv.tcp, &buf, 1, write_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value1, value2;
  mrb_uv_context* context;
  struct sockaddr_in* addr = NULL;

  value1 = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value1, &uv_context_type, context);

  mrb_get_args(mrb, "o", &arg);
  if (mrb_nil_p(arg) || strcmp(mrb_obj_classname(mrb, arg), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value2 = mrb_iv_get(mrb, arg, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value2, &uv_ip4addr_type, addr);

  if (uv_tcp_bind(&context->uv.tcp, *addr) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_connection_cb(uv_stream_t* handle, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_yield(context->mrb, context->proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_tcp_listen(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_value value;
  mrb_uv_context* context;
  struct RProc *b;
  uv_connection_cb connection_cb = _uv_connection_cb;

  value = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value, &uv_context_type, context);

  mrb_get_args(mrb, "bi", &b, &arg);
  if (b) context->proc = mrb_obj_value(b);
  else connection_cb = NULL;
  /* guard reference: avoid to free */
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), context->proc);

  if (uv_listen((uv_stream_t*) &context->uv.tcp, mrb_fixnum(arg), connection_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c, value1, value2;
  mrb_uv_context* context;
  mrb_uv_context* new_context;

  value1 = mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value1, &uv_context_type, context);

#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::TCP"));
#else
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_tcp);
#endif
  value2 = mrb_iv_get(mrb, c, mrb_intern(mrb, "data"));
  Data_Get_Struct(mrb, value2, &uv_context_type, new_context);

  new_context->loop = context->loop;

  if (uv_accept((uv_stream_t*) &context->uv.tcp, (uv_stream_t*) &new_context->uv.tcp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }

  return c;
}

/*********************************************************
 * register
 *********************************************************/

void
name_class(mrb_state *mrb, struct RClass *p, struct RClass *c, const char* name)
{
  mrb_iv_set(mrb, mrb_obj_value(p), mrb_intern(mrb, name), mrb_obj_value(c));
}

void
mrb_uv_init(mrb_state* mrb) {
  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  mrb_define_class_method(mrb, _class_uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_class_method(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));

  _class_uv_loop = mrb_define_class_under(mrb, _class_uv, "Loop", mrb->object_class);
  mrb_define_method(mrb, _class_uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run", mrb_uv_loop_run, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run_once", mrb_uv_loop_run_once, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "ref", mrb_uv_loop_ref, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "unref", mrb_uv_loop_unref, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_delete, ARGS_NONE());

  _class_uv_timer = mrb_define_class_under(mrb, _class_uv, "Timer", mrb->object_class);
  mrb_define_method(mrb, _class_uv_timer, "initialize", mrb_uv_timer_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, _class_uv_timer, "stop", mrb_uv_timer_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "close", mrb_uv_close, ARGS_OPT(1));

  _class_uv_idle = mrb_define_class_under(mrb, _class_uv, "Idle", mrb->object_class);
  mrb_define_method(mrb, _class_uv_idle, "initialize", mrb_uv_idle_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_idle, "start", mrb_uv_idle_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_idle, "stop", mrb_uv_idle_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "close", mrb_uv_close, ARGS_OPT(1));

  _class_uv_ip4addr = mrb_define_class_under(mrb, _class_uv, "Ip4Addr", mrb->object_class);
  mrb_define_method(mrb, _class_uv_ip4addr, "initialize", mrb_uv_ip4addr_init, ARGS_REQ(2));

  _class_uv_tcp = mrb_define_class_under(mrb, _class_uv, "TCP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "write", mrb_uv_write, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "bind", mrb_uv_tcp_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "listen", mrb_uv_tcp_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "accept", mrb_uv_tcp_accept, ARGS_OPT(1));
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
