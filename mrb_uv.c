#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include <uv.h>
#include <stdio.h>

typedef struct {
  mrb_state* mrb;
  uv_loop_t* loop;
  union {
     uv_tcp_t tcp;
     uv_udp_t udp;
     uv_pipe_t pipe;
     uv_idle_t idle;
     uv_timer_t timer;
     uv_loop_t loop;
     uv_handle_t handle;
     uv_stream_t stream;
  } uv;
  mrb_value instance; /* callback */
} mrb_uv_context;

static mrb_uv_context*
uv_context_alloc(mrb_state* mrb, mrb_value instance, size_t size)
{
  mrb_uv_context* context = (mrb_uv_context*) mrb_malloc(mrb, sizeof(mrb_uv_context));
  memset(context, 0, sizeof(mrb_uv_context));
  context->loop = uv_default_loop();
  context->mrb = mrb;
  context->instance = instance;
  return context;
}

static void
uv_context_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, p);
}

static const struct mrb_data_type uv_context_type = {
  "uv_context", uv_context_free,
};

static void
uv_ip4addr_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, p);
}

static const struct mrb_data_type uv_ip4addr_type = {
  "uv_ip4addr", uv_ip4addr_free,
};

static struct RClass *_class_uv;
static struct RClass *_class_uv_loop;
static struct RClass *_class_uv_timer;
static struct RClass *_class_uv_idle;
static struct RClass *_class_uv_tcp;
static struct RClass *_class_uv_udp;
static struct RClass *_class_uv_pipe;
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

static mrb_value
mrb_uv_run_once(mrb_state *mrb, mrb_value self)
{
  if (uv_run_once(uv_default_loop()) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static void
_uv_close_cb(uv_handle_t* handle)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "close_cb"));
  mrb_yield_argv(context->mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_close_cb close_cb = _uv_close_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "b", &b);
  if (!b) close_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "close_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  uv_close(&context->uv.handle, close_cb);
  return mrb_nil_value();
}

static uv_buf_t
_uv_alloc_cb(uv_handle_t* handle, size_t suggested_size)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  return uv_buf_init(mrb_malloc(context->mrb, suggested_size), suggested_size);
}

static void
_uv_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) stream->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "read_cb"));
  if (nread == -1) {
    mrb_yield(context->mrb, proc, mrb_nil_value());
  } else {
    mrb_yield(context->mrb, proc, mrb_str_new(context->mrb, buf.base, nread));
  }
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_read_cb read_cb = _uv_read_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "b", &b);
  if (!b) read_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "read_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_read_start(&context->uv.stream, _uv_alloc_cb, read_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_read_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_read_stop(&context->uv.stream) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_write_cb(uv_write_t* req, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "write_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_write_cb write_cb = _uv_write_cb;
  static uv_write_t req = {0};
  static uv_buf_t buf;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bo", &b, &arg_data);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (!b) write_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "write_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_CAPA(arg_data));
  if (uv_write(&req, &context->uv.stream, &buf, 1, write_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_connection_cb(uv_stream_t* handle, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "connection_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "connect_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

/*********************************************************
 * Loop
 *********************************************************/
static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_context* context = NULL;

#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::Loop"));
#else
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_loop);
#endif
  context = uv_context_alloc(mrb, c, sizeof(uv_loop_t));
  context->uv.loop = *uv_default_loop();
  mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_context* context = uv_context_alloc(mrb, self, sizeof(uv_loop_t));
  context->uv.loop = *uv_loop_new();
  context->uv.loop.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_run(&context->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&context->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_run_once(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_run_once(&context->uv.loop) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(&context->uv.loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_ref(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_ref(&context->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_unref(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_unref(&context->uv.loop);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_loop_delete(&context->uv.loop);
  return mrb_nil_value();
}

/*********************************************************
 * Timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }

    loop = &loop_context->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self, sizeof(uv_timer_t));
  context->loop = loop;
  if (uv_timer_init(loop, &context->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.timer.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_timer_cb(uv_timer_t* timer, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) timer->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "timer_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_timeout, arg_repeat;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_timer_cb timer_cb = _uv_timer_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bii", &b, &arg_timeout, &arg_repeat);
  if (!b) timer_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "timer_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_timer_start(&context->uv.timer, timer_cb,
      mrb_fixnum(arg_timeout), mrb_fixnum(arg_repeat)) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_timer_stop(&context->uv.timer) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = &loop_context->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self, sizeof(uv_idle_t));
  context->loop = loop;
  if (uv_idle_init(loop, &context->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.idle.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) idle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "idle_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_idle_cb idle_cb = _uv_idle_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "b", &b);
  if (!b) idle_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "idle_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_idle_start(&context->uv.idle, idle_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_idle_stop(&context->uv.idle) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Ip4Addr / Ip6Addr
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
  mrb_value arg_host, arg_port;
  struct sockaddr_in vaddr;
  struct sockaddr_in *addr = NULL;

  mrb_get_args(mrb, "oi", &arg_host, &arg_port);
  if (!mrb_nil_p(arg_host) && !mrb_nil_p(arg_port)) {
    vaddr = uv_ip4_addr((const char*) RSTRING_PTR(arg_host), mrb_fixnum(arg_port));
    addr = (struct sockaddr_in*) mrb_malloc(mrb, sizeof(struct sockaddr_in));
    memcpy(addr, &vaddr, sizeof(vaddr));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_ip4addr_type, (void*) addr)));
  return self;
}

static mrb_value
mrb_uv_ip4addr_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr;
  struct sockaddr_in* addr = NULL;
  char name[256];

  value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    return mrb_nil_value();
  }
  if (uv_ip4_name(addr, name, sizeof(name)) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_str_new(mrb, name, strlen(name));
}

/*********************************************************
 * TCP
 *********************************************************/
static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = &loop_context->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self, sizeof(uv_tcp_t));
  context->loop = loop;
  if (uv_tcp_init(loop, &context->uv.tcp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.tcp.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_addr;
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_connect_cb connect_cb = _uv_connect_cb;
  static uv_connect_t req;
  struct sockaddr_in* addr = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bo", &b, &arg_addr);
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (!b) connect_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_tcp_connect(&req, &context->uv.tcp, *addr, connect_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_addr;
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_in* addr = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "o", &arg_addr);
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_tcp_bind(&context->uv.tcp, *addr) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_listen(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_backlog;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_connection_cb connection_cb = _uv_connection_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bi", &b, &arg_backlog);
  if (!b) connection_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_listen((uv_stream_t*) &context->uv.tcp, mrb_fixnum(arg_backlog), connection_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c, value_context, value_new_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* new_context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::TCP"));
#else
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_tcp);
#endif
  value_new_context = mrb_iv_get(mrb, c, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_new_context, &uv_context_type, new_context);

  new_context->loop = context->loop;

  if (uv_accept((uv_stream_t*) &context->uv.tcp, (uv_stream_t*) &new_context->uv.tcp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }

  return c;
}

/*********************************************************
 * UDP
 *********************************************************/
static mrb_value
mrb_uv_udp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = &loop_context->uv.loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self, sizeof(uv_udp_t));
  context->loop = loop;
  if (uv_udp_init(loop, &context->uv.udp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.udp.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_udp_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_addr, arg_flags;
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_in* addr = NULL;
  int flags = 0;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "oi", &arg_addr, &arg_flags);
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), "UV::Ip4Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (!mrb_nil_p(arg_flags)) {
    flags = mrb_fixnum(arg_flags);
  }

  if (uv_udp_bind(&context->uv.udp, *addr, flags) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_udp_send_cb(uv_udp_send_t* req, int status)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "udp_send_cb"));
  mrb_yield(context->mrb, proc, mrb_fixnum_value(status));
}

static mrb_value
mrb_uv_udp_send(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data, arg_addr;
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_in* addr = NULL;
  struct RProc *b = NULL;
  uv_udp_send_cb udp_send_cb = _uv_udp_send_cb;
  static uv_udp_send_t req = {0};
  static uv_buf_t buf;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "boo", &b, &arg_data, &arg_addr);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (!b) udp_send_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "udp_send_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_CAPA(arg_data));
  if (uv_udp_send(&req, &context->uv.udp, &buf, 1, *addr, udp_send_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "udp_recv_cb"));
  mrb_value args[3];
  if (nread != -1) {
    mrb_value c;
    c = mrb_class_new_instance(context->mrb, 0, NULL, _class_uv_ip4addr);
    mrb_iv_set(context->mrb, c, mrb_intern(context->mrb, "context"), mrb_obj_value(
      Data_Wrap_Struct(context->mrb, context->mrb->object_class,
      &uv_ip4addr_type, (void*) addr)));
    args[0] = mrb_str_new(context->mrb, buf.base, nread);
    args[1] = c;
    args[2] = mrb_fixnum_value(flags);
  } else {
    args[0] = mrb_nil_value();
    args[1] = mrb_nil_value();
    args[2] = mrb_fixnum_value(flags);
  }
  mrb_yield_argv(context->mrb, proc, 3, args);
}

static mrb_value
mrb_uv_udp_recv_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_udp_recv_cb udp_recv_cb = _uv_udp_recv_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "b", &b);
  if (!b) udp_recv_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "udp_recv_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_udp_recv_start(&context->uv.udp, _uv_alloc_cb, udp_recv_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_recv_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_udp_recv_stop(&context->uv.udp) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Pipe
 *********************************************************/
static mrb_value
mrb_uv_pipe_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop, arg_ipc;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;
  int ipc = 1;

  mrb_get_args(mrb, "oi", &arg_loop, &arg_ipc);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = &loop_context->uv.loop;
  } else {
    loop = uv_default_loop();
  }
  if (!mrb_nil_p(arg_ipc)) {
    ipc = mrb_fixnum(arg_ipc);
  }

  context = uv_context_alloc(mrb, self, sizeof(uv_pipe_t));
  context->loop = loop;
  if (uv_pipe_init(loop, &context->uv.pipe, ipc) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->uv.pipe.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_pipe_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_name;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_connect_cb connect_cb = _uv_connect_cb;
  static uv_connect_t req;
  char* name = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bo", &b, &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  if (!b) connect_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  uv_pipe_connect(&req, &context->uv.pipe, name, connect_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_name;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  char* name = "";

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "o", &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  if (uv_pipe_bind(&context->uv.pipe, name ? name : "") != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_listen(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_backlog;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_connection_cb connection_cb = _uv_connection_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "bi", &b, &arg_backlog);
  if (!b) connection_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_listen((uv_stream_t*) &context->uv.pipe, mrb_fixnum(arg_backlog), connection_cb) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c, value_context, value_new_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* new_context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::Pipe"));
#else
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_pipe);
#endif
  value_new_context = mrb_iv_get(mrb, c, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_new_context, &uv_context_type, new_context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  new_context->loop = context->loop;

  if (uv_accept((uv_stream_t*) &context->uv.pipe, (uv_stream_t*) &new_context->uv.pipe) != 0) {
    mrb_raise(mrb, E_SYSTEMCALL_ERROR, uv_strerror(uv_last_error(context->loop)));
  }

  return c;
}

/*********************************************************
 * register
 *********************************************************/

void
mrb_uv_init(mrb_state* mrb) {
  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_class_method(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  mrb_define_class_method(mrb, _class_uv, "run_once", mrb_uv_run_once, ARGS_NONE());
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
  mrb_define_method(mrb, _class_uv_ip4addr, "to_s", mrb_uv_ip4addr_to_s, ARGS_NONE());

  _class_uv_tcp = mrb_define_class_under(mrb, _class_uv, "TCP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "write", mrb_uv_write, ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_tcp, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "bind", mrb_uv_tcp_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "listen", mrb_uv_tcp_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "accept", mrb_uv_tcp_accept, ARGS_NONE());

  _class_uv_udp = mrb_define_class_under(mrb, _class_uv, "UDP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_udp, "initialize", mrb_uv_udp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_udp, "recv_start", mrb_uv_udp_recv_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "recv_stop", mrb_uv_udp_recv_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send", mrb_uv_udp_send, ARGS_OPT(3));
  mrb_define_method(mrb, _class_uv_udp, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_udp, "bind", mrb_uv_udp_bind, ARGS_REQ(1));

  _class_uv_pipe = mrb_define_class_under(mrb, _class_uv, "Pipe", mrb->object_class);
  mrb_define_method(mrb, _class_uv_pipe, "initialize", mrb_uv_pipe_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_pipe, "connect", mrb_uv_pipe_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "write", mrb_uv_write, ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_pipe, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_pipe, "bind", mrb_uv_pipe_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "listen", mrb_uv_pipe_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "accept", mrb_uv_pipe_accept, ARGS_NONE());
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
