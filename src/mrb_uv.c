#include <errno.h>
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
#include <fcntl.h>

typedef struct {
  union {
    uv_tcp_t tcp;
    uv_udp_t udp;
    uv_pipe_t pipe;
    uv_idle_t idle;
    uv_timer_t timer;
    uv_async_t async;
    uv_prepare_t prepare;
    uv_handle_t handle;
    uv_stream_t stream;
    uv_mutex_t mutex;
    uv_file fs;
  } any;
  mrb_value instance; /* callback */
  uv_loop_t* loop;
  mrb_state* mrb;
} mrb_uv_context;

static mrb_uv_context*
uv_context_alloc(mrb_state* mrb, mrb_value instance)
{
  mrb_uv_context* context = (mrb_uv_context*) malloc(sizeof(mrb_uv_context));
  memset(context, 0, sizeof(mrb_uv_context));
  context->loop = uv_default_loop();
  context->mrb = mrb;
  context->instance = instance;
  return context;
}

static void
uv_context_free(mrb_state *mrb, void *p)
{
  ((mrb_uv_context*) p)->mrb = NULL;
  free(p);
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
static struct RClass *_class_uv_async;
static struct RClass *_class_uv_tcp;
static struct RClass *_class_uv_udp;
static struct RClass *_class_uv_pipe;
static struct RClass *_class_uv_ip4addr;
static struct RClass *_class_uv_prepare;
static struct RClass *_class_uv_mutex;
static struct RClass *_class_uv_fs;

/*********************************************************
 * main
 *********************************************************/
static mrb_value
mrb_uv_run(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_run(uv_default_loop()));
}

static mrb_value
mrb_uv_run_once(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_run_once(uv_default_loop()));
}

static void
_uv_close_cb(uv_handle_t* handle)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "close_cb"));
  mrb_yield(context->mrb, proc, context->instance);
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

  mrb_get_args(mrb, "|&", &b);
  if (!b) close_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "close_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  uv_close(&context->any.handle, close_cb);
  return mrb_nil_value();
}

static void
_uv_shutdown_cb(uv_shutdown_t* req, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "shutdown_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
  mrb_free(context->mrb, req);
}

static mrb_value
mrb_uv_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_shutdown_cb shutdown_cb = _uv_shutdown_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&", &b);
  if (!b) shutdown_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "shutdown_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_shutdown_t req;
  uv_shutdown(&req, &context->any.stream, shutdown_cb);
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
  if (!uv_is_active(&context->any.handle))
    return;
  int ai = mrb_gc_arena_save(context->mrb);
  if (nread == -1) {
    mrb_yield(context->mrb, proc, context->instance);
  } else {
    mrb_value args[2];
    args[0] = context->instance;
    args[1] = mrb_str_new(context->mrb, buf.base, nread);
    mrb_yield_argv(context->mrb, proc, 2, args);
  }
  mrb_gc_arena_restore(context->mrb, ai);
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

  mrb_get_args(mrb, "&", &b);
  if (!b) read_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "read_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_read_start(&context->any.stream, _uv_alloc_cb, read_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_read_stop(&context->any.stream) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_write_cb(uv_write_t* req, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  if (!uv_is_active(&context->any.handle))
    return;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "write_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
  mrb_free(context->mrb, req);
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_write_cb write_cb = _uv_write_cb;
  uv_buf_t buf;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&o", &b, &arg_data);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (!b) write_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "write_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  static uv_write_t req;
  if (uv_write(&req, &context->any.stream, &buf, 1, write_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_connection_cb(uv_stream_t* handle, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "connection_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "connect_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
  mrb_free(context->mrb, req);
}

static mrb_value
mrb_uv_data_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "data"));
}

static mrb_value
mrb_uv_data_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "data"), arg);
  return mrb_nil_value();
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
  context = uv_context_alloc(mrb, c);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = uv_default_loop();
  mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_context* context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = uv_loop_new();
  context->loop->data = context;
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

  if (uv_run(context->loop) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_run_once(context->loop) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
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

  uv_loop_delete(context->loop);
  return mrb_nil_value();
}

/*********************************************************
 * Timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }

    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_timer_init(loop, &context->any.timer) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.timer.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_timer_cb(uv_timer_t* timer, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) timer->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "timer_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
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

  mrb_get_args(mrb, "&ii", &b, &arg_timeout, &arg_repeat);
  if (!b) timer_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "timer_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_timer_start(&context->any.timer, timer_cb,
      mrb_fixnum(arg_timeout), mrb_fixnum(arg_repeat)) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_timer_stop(&context->any.timer) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_idle_init(loop, &context->any.idle) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.idle.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) idle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "idle_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
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

  mrb_get_args(mrb, "&", &b);
  if (!b) idle_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "idle_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_idle_start(&context->any.idle, idle_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_idle_stop(&context->any.idle) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Async
 *********************************************************/
static void
_uv_async_cb(uv_async_t* async, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) async->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "async_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
}

static mrb_value
mrb_uv_async_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;
  struct RProc *b = NULL;
  uv_async_cb async_cb = _uv_async_cb;

  if (mrb_get_args(mrb, "&|o", &b, &arg_loop) == 1) {
    mrb_value obj = mrb_funcall(mrb, arg_loop, "inspect", 0);
    fwrite(RSTRING_PTR(obj), RSTRING_LEN(obj), 1, stdout);

    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  if (!b) async_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "async_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_async_init(loop, &context->any.async, async_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.async.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_async_send(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_async_send(&context->any.async) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Prepare
 *********************************************************/
static void
_uv_prepare_cb(uv_prepare_t* prepare, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) prepare->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "prepare_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
}

static mrb_value
mrb_uv_prepare_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_prepare_init(loop, &context->any.prepare) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.prepare.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_prepare_start(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_prepare_cb prepare_cb = _uv_prepare_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (!b) prepare_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "prepare_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_prepare_start(&context->any.prepare, prepare_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_prepare_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (uv_prepare_stop(&context->any.prepare) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Mutex
 *********************************************************/
static mrb_value
mrb_uv_mutex_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_context* context = NULL;
  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = uv_default_loop();
  if (uv_mutex_init(&context->any.mutex) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_mutex_lock(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_mutex_lock(&context->any.mutex);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_mutex_unlock(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_mutex_unlock(&context->any.mutex);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_mutex_trylock(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(uv_mutex_trylock(&context->any.mutex));
}

static mrb_value
mrb_uv_mutex_destroy(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_mutex_destroy(&context->any.mutex);
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
  mrb_value arg_host = mrb_nil_value(), arg_port = mrb_nil_value();
  struct sockaddr_in vaddr;
  struct sockaddr_in *addr = NULL;

  mrb_get_args(mrb, "oi", &arg_host, &arg_port);
  if (!mrb_nil_p(arg_host) && !mrb_nil_p(arg_port)) {
    vaddr = uv_ip4_addr((const char*) strdup(RSTRING_PTR(arg_host)), mrb_fixnum(arg_port));
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
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_str_new(mrb, name, strlen(name));
}

/*********************************************************
 * TCP
 *********************************************************/
static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_tcp_init(loop, &(context->any.tcp)) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.tcp.data = context;
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
  struct sockaddr_in* addr = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&o", &b, &arg_addr);
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

  static uv_connect_t req;
  if (uv_tcp_connect(&req, &context->any.tcp, *addr, connect_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_addr = mrb_nil_value();
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

  if (uv_tcp_bind(&context->any.tcp, *addr) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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
  int backlog;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (!b) connection_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b ? mrb_obj_value(b) : mrb_nil_value());
  backlog = mrb_fixnum(arg_backlog);

  if (uv_listen((uv_stream_t*) &context->any.tcp, backlog, connection_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_accept((uv_stream_t*) &context->any.tcp, (uv_stream_t*) &new_context->any.tcp) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }

  return c;
}

/*
static mrb_value
mrb_uv_tcp_simultaneous_accepts_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "simultaneous_accepts"));
}
*/

static mrb_value
mrb_uv_tcp_simultaneous_accepts_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_simultaneous_accepts;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  int simultaneous_accepts;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_simultaneous_accepts);
  simultaneous_accepts = mrb_fixnum(arg_simultaneous_accepts);
  /*
  mrb_iv_set(mrb, self, mrb_intern(mrb, "simultaneous_accepts"), mrb_fixnum_value(simultaneous_accepts));
  */
  uv_tcp_simultaneous_accepts(&context->any.tcp, simultaneous_accepts);
  return mrb_nil_value();
}

/*
static mrb_value
mrb_uv_tcp_keepalive_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "keepalive"));
}
*/

static mrb_value
mrb_uv_tcp_keepalive_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_keepalive, arg_delay;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  int keepalive, delay;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "ii", &arg_keepalive, &arg_delay);
  keepalive = mrb_fixnum(arg_keepalive);
  delay = mrb_fixnum(arg_delay);
  /*
  mrb_iv_set(mrb, self, mrb_intern(mrb, "keepalive"), mrb_fixnum_value(keepalive));
  mrb_iv_set(mrb, self, mrb_intern(mrb, "delay"), mrb_fixnum_value(delay));
  */
  uv_tcp_keepalive(&context->any.tcp, keepalive, delay);
  return mrb_nil_value();
}

/*
static mrb_value
mrb_uv_tcp_nodelay_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "nodelay"));
}
*/

static mrb_value
mrb_uv_tcp_nodelay_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_nodelay;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  int nodelay;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_nodelay);
  nodelay = mrb_fixnum(arg_nodelay);
  /*
  mrb_iv_set(mrb, self, mrb_intern(mrb, "nodelay"), mrb_fixnum_value(nodelay));
  */
  uv_tcp_nodelay(&context->any.tcp, nodelay);
  return mrb_nil_value();
}

/*********************************************************
 * UDP
 *********************************************************/
static mrb_value
mrb_uv_udp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  if (!mrb_nil_p(arg_loop)) {
    if (strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
    Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
    if (!loop_context) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    loop = loop_context->loop;
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_udp_init(loop, &context->any.udp) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.udp.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_udp_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_addr = mrb_nil_value(), arg_flags = mrb_nil_value();
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_in* addr = NULL;
  int flags = 0;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "o|i", &arg_addr, &arg_flags);
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

  if (uv_udp_bind(&context->any.udp, *addr, flags) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_udp_send_cb(uv_udp_send_t* req, int status)
{
  mrb_value proc;
  mrb_value args[2];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "udp_send_cb"));
  args[0] = context->instance;
  args[1] = mrb_fixnum_value(status);
  mrb_yield_argv(context->mrb, proc, 2, args);
  mrb_free(context->mrb, req);
}

static mrb_value
mrb_uv_udp_send(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value(), arg_addr = mrb_nil_value();
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_in* addr = NULL;
  struct RProc *b = NULL;
  uv_udp_send_cb udp_send_cb = _uv_udp_send_cb;
  uv_buf_t buf;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&oo", &b, &arg_data, &arg_addr);
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

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  static uv_udp_send_t req;
  if (uv_udp_send(&req, &context->any.udp, &buf, 1, *addr, udp_send_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

static void
_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "udp_recv_cb"));
  mrb_value args[4];
  args[0] = context->instance;
  int ai = mrb_gc_arena_save(context->mrb);
  if (nread != -1) {
    char name[256];
    mrb_value c;
    mrb_value addr_args[2];
    if (uv_ip4_name((struct sockaddr_in*) addr, name, sizeof(name)) != 0) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    addr_args[0] = mrb_str_new(mrb, name, strlen(name));
    addr_args[1] = mrb_fixnum_value(ntohs(((struct sockaddr_in*)addr)->sin_port));
    c = mrb_class_new_instance(mrb, 2, addr_args, _class_uv_ip4addr);
    mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
      Data_Wrap_Struct(mrb, mrb->object_class,
      &uv_ip4addr_type, (void*) addr)));
    args[1] = mrb_str_new(mrb, buf.base, nread);
    args[2] = c;
  } else {
    args[1] = mrb_nil_value();
    args[2] = mrb_nil_value();
  }
  args[3] = mrb_fixnum_value(flags);
  mrb_yield_argv(mrb, proc, 4, args);
  mrb_gc_arena_restore(context->mrb, ai);
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

  mrb_get_args(mrb, "&", &b);
  if (!b) udp_recv_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "udp_recv_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_udp_recv_start(&context->any.udp, _uv_alloc_cb, udp_recv_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  if (uv_udp_recv_stop(&context->any.udp) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_nil_value();
}

/*********************************************************
 * Pipe
 *********************************************************/
static mrb_value
mrb_uv_pipe_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value(), arg_ipc = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;
  int ipc = 0;

  mrb_get_args(mrb, "|oi", &arg_loop, &arg_ipc);
  if (!mrb_nil_p(arg_loop)) {
    if (!strcmp(mrb_obj_classname(mrb, arg_loop), "UV::Loop")) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
      value_context = mrb_iv_get(mrb, arg_loop, mrb_intern(mrb, "context"));
      Data_Get_Struct(mrb, value_context, &uv_context_type, loop_context);
      if (!loop_context) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
      }
      loop = loop_context->loop;
    } else {
      loop = uv_default_loop();
      arg_ipc = arg_loop;
    }
  } else {
    loop = uv_default_loop();
  }
  if (!mrb_nil_p(arg_ipc)) {
    ipc = mrb_fixnum(arg_ipc);
  }

  context = uv_context_alloc(mrb, self);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }
  context->loop = loop;
  if (uv_pipe_init(loop, &context->any.pipe, ipc) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(loop)));
  }
  context->any.pipe.data = context;
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
  char* name = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&o", &b, &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  if (!b) connect_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_connect_t req;
  uv_pipe_connect(&req, &context->any.pipe, name, connect_cb);
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

  if (uv_pipe_bind(&context->any.pipe, name ? name : "") != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (!b) connection_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  if (uv_listen((uv_stream_t*) &context->any.pipe, mrb_fixnum(arg_backlog), connection_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
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

  mrb_value args[1];
  args[0] = mrb_fixnum_value(0);
#if 0
  c = mrb_class_new_instance(mrb, 0, NULL, mrb_class_get(mrb, "UV::Pipe"));
#else
  c = mrb_class_new_instance(mrb, 1, args, _class_uv_pipe);
#endif
  value_new_context = mrb_iv_get(mrb, c, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_new_context, &uv_context_type, new_context);
  if (!new_context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  new_context->loop = context->loop;

  if (uv_accept((uv_stream_t*) &context->any.pipe, (uv_stream_t*) &new_context->any.pipe) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }

  return c;
}

/*********************************************************
 * FS
 *********************************************************/
static void
_uv_fs_cb(uv_fs_t* req)
{
  mrb_value proc;
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) req->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "fs_cb"));
  args[0] = context->instance;
  mrb_yield_argv(context->mrb, proc, 1, args);
  mrb_free(context->mrb, req);
}

static mrb_value
mrb_uv_fs_open(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_filename = mrb_nil_value(), arg_mode = mrb_nil_value();
  mrb_value arg_flags;
  uv_fs_cb fs_cb = _uv_fs_cb;
  struct RProc *b = NULL;

  mrb_get_args(mrb, "&oii", &b, &arg_filename, &arg_flags, &arg_mode);

  mrb_value c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_fs);
  if (!b) fs_cb = NULL;

  mrb_uv_context* context = uv_context_alloc(mrb, c);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't memory alloc");
  }

  context->loop = uv_default_loop();
  mrb_iv_set(mrb, c, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());
  mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  context->any.fs = uv_fs_open(uv_default_loop(), &req, RSTRING_PTR(arg_filename), mrb_fixnum(arg_flags), mrb_fixnum(arg_mode), fs_cb);
  if (context->any.fs == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }

  return c;
}

static void
_uv_fs_close_cb(uv_fs_t* req)
{
  mrb_value proc;
  mrb_uv_context* context = (mrb_uv_context*) req->data;
  proc = mrb_iv_get(context->mrb, context->instance, mrb_intern(context->mrb, "fs_cb"));
  mrb_yield(context->mrb, proc, context->instance);
}

static mrb_value
mrb_uv_fs_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&", &b);
  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  uv_fs_close(uv_default_loop(), &req, context->any.fs, fs_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value(), arg_offset = mrb_fixnum_value(0);
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&oi", &b, &arg_data, &arg_offset);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  int r = uv_fs_write(uv_default_loop(), &req, context->any.fs, RSTRING_PTR(arg_data), RSTRING_LEN(arg_data), mrb_fixnum(arg_offset), fs_cb);
  if (r == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  return mrb_fixnum_value(r);
}

static mrb_value
mrb_uv_fs_read(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_length = mrb_fixnum_value(BUFSIZ);
  mrb_value arg_offset = mrb_fixnum_value(-1);
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|&ii", &b, &arg_length, &arg_offset);

  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  size_t len = mrb_fixnum(arg_length);
  char* buf = malloc(len);
  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  len = uv_fs_read(uv_default_loop(), &req, context->any.fs, buf, len, mrb_fixnum(arg_offset), fs_cb);
  if (len == -1) {
    free(buf);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(context->loop)));
  }
  mrb_value str = mrb_str_new(mrb, buf, len);
  free(buf);
  return str;
}

static mrb_value
mrb_uv_fs_unlink(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path;
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  mrb_get_args(mrb, "|&o", &b, &arg_path);
  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(uv_default_loop(), &req, RSTRING_PTR(arg_path), fs_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_mkdir(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path = mrb_nil_value(), arg_mode = mrb_fixnum_value(0755);
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  mrb_get_args(mrb, "|&oi", &b, &arg_path, &arg_mode);
  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(uv_default_loop(), &req, RSTRING_PTR(arg_path), mrb_fixnum(arg_mode), fs_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_rmdir(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path;
  struct RProc *b = NULL;
  uv_fs_cb fs_cb = _uv_fs_cb;

  mrb_get_args(mrb, "|&o", &b, &arg_path);
  if (!b) fs_cb = NULL;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b ? mrb_obj_value(b) : mrb_nil_value());

  static uv_fs_t req;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(uv_default_loop(), &req, RSTRING_PTR(arg_path), fs_cb) != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(uv_last_error(uv_default_loop())));
  }
  return mrb_nil_value();
}

/*********************************************************
 * register
 *********************************************************/

void
mrb_mruby_uv_gem_init(mrb_state* mrb) {
  int ai;

  _class_uv = mrb_define_module(mrb, "UV");

  ai = mrb_gc_arena_save(mrb);
  mrb_define_module_function(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "run_once", mrb_uv_run_once, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_loop = mrb_define_class_under(mrb, _class_uv, "Loop", mrb->object_class);
  mrb_define_method(mrb, _class_uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run", mrb_uv_loop_run, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run_once", mrb_uv_loop_run_once, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_delete, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_timer = mrb_define_class_under(mrb, _class_uv, "Timer", mrb->object_class);
  mrb_define_method(mrb, _class_uv_timer, "initialize", mrb_uv_timer_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(3));
  mrb_define_method(mrb, _class_uv_timer, "stop", mrb_uv_timer_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_timer, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_timer, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_idle = mrb_define_class_under(mrb, _class_uv, "Idle", mrb->object_class);
  mrb_define_method(mrb, _class_uv_idle, "initialize", mrb_uv_idle_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_idle, "start", mrb_uv_idle_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_idle, "stop", mrb_uv_idle_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_idle, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_idle, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_async = mrb_define_class_under(mrb, _class_uv, "Async", mrb->object_class);
  mrb_define_method(mrb, _class_uv_async, "initialize", mrb_uv_async_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_async, "send", mrb_uv_async_send, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_async, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_prepare = mrb_define_class_under(mrb, _class_uv, "Prepare", mrb->object_class);
  mrb_define_method(mrb, _class_uv_prepare, "initialize", mrb_uv_prepare_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_prepare, "start", mrb_uv_prepare_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "stop", mrb_uv_prepare_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_ip4addr = mrb_define_class_under(mrb, _class_uv, "Ip4Addr", mrb->object_class);
  mrb_define_method(mrb, _class_uv_ip4addr, "initialize", mrb_uv_ip4addr_init, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_ip4addr, "to_s", mrb_uv_ip4addr_to_s, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_tcp = mrb_define_class_under(mrb, _class_uv, "TCP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "write", mrb_uv_write, ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_tcp, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "shutdown", mrb_uv_shutdown, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_tcp, "bind", mrb_uv_tcp_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "listen", mrb_uv_tcp_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "accept", mrb_uv_tcp_accept, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "simultaneous_accepts=", mrb_uv_tcp_simultaneous_accepts_set, ARGS_REQ(1));
  //mrb_define_method(mrb, _class_uv_tcp, "simultaneous_accepts", mrb_uv_tcp_simultaneous_accepts_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "keepalive=", mrb_uv_tcp_keepalive_set, ARGS_REQ(1));
  //mrb_define_method(mrb, _class_uv_tcp, "keepalive", mrb_uv_tcp_keepalive_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "nodelay=", mrb_uv_tcp_nodelay_set, ARGS_REQ(1));
  //mrb_define_method(mrb, _class_uv_tcp, "nodelay", mrb_uv_tcp_nodelay_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_udp = mrb_define_class_under(mrb, _class_uv, "UDP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_udp, "initialize", mrb_uv_udp_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_udp, "recv_start", mrb_uv_udp_recv_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "recv_stop", mrb_uv_udp_recv_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send", mrb_uv_udp_send, ARGS_OPT(3));
  mrb_define_method(mrb, _class_uv_udp, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_udp, "bind", mrb_uv_udp_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_pipe = mrb_define_class_under(mrb, _class_uv, "Pipe", mrb->object_class);
  mrb_define_method(mrb, _class_uv_pipe, "initialize", mrb_uv_pipe_init, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_pipe, "connect", mrb_uv_pipe_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "write", mrb_uv_write, ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_pipe, "close", mrb_uv_close, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_pipe, "shutdown", mrb_uv_shutdown, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_pipe, "bind", mrb_uv_pipe_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "listen", mrb_uv_pipe_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "accept", mrb_uv_pipe_accept, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "data", mrb_uv_data_get, ARGS_NONE());

  ai = mrb_gc_arena_save(mrb);
  _class_uv_mutex = mrb_define_class_under(mrb, _class_uv, "Mutex", mrb->object_class);
  mrb_define_method(mrb, _class_uv_mutex, "initialize", mrb_uv_mutex_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "lock", mrb_uv_mutex_lock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "trylock", mrb_uv_mutex_trylock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "unlock", mrb_uv_mutex_unlock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "destroy", mrb_uv_mutex_destroy, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_mutex, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  ai = mrb_gc_arena_save(mrb);
  _class_uv_fs = mrb_define_class_under(mrb, _class_uv, "FS", mrb->object_class);
  mrb_define_const(mrb, _class_uv_fs, "O_RDONLY", mrb_fixnum_value(O_RDONLY));
  mrb_define_const(mrb, _class_uv_fs, "O_WRONLY", mrb_fixnum_value(O_WRONLY));
  mrb_define_const(mrb, _class_uv_fs, "O_RDWR", mrb_fixnum_value(O_RDWR));
  mrb_define_const(mrb, _class_uv_fs, "O_CREAT", mrb_fixnum_value(O_CREAT));
  mrb_define_const(mrb, _class_uv_fs, "O_TRUNC", mrb_fixnum_value(O_TRUNC));
  mrb_define_const(mrb, _class_uv_fs, "O_APPEND", mrb_fixnum_value(O_APPEND));
  mrb_define_const(mrb, _class_uv_fs, "O_TEXT", mrb_fixnum_value(O_TEXT));
  mrb_define_const(mrb, _class_uv_fs, "O_BINARY", mrb_fixnum_value(O_BINARY));
  mrb_define_const(mrb, _class_uv_fs, "S_IWRITE", mrb_fixnum_value(S_IWRITE));
  mrb_define_const(mrb, _class_uv_fs, "S_IREAD", mrb_fixnum_value(S_IREAD));
  mrb_define_module_function(mrb, _class_uv_fs, "open", mrb_uv_fs_open, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_fs, "write", mrb_uv_fs_write, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_fs, "read", mrb_uv_fs_read, ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_fs, "close", mrb_uv_fs_close, ARGS_OPT(1));
  mrb_define_module_function(mrb, _class_uv_fs, "unlink", mrb_uv_fs_unlink, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "mkdir", mrb_uv_fs_mkdir, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "rmdir", mrb_uv_fs_rmdir, ARGS_OPT(1));
  mrb_define_module_function(mrb, _class_uv_fs, "rmdir", mrb_uv_fs_rmdir, ARGS_OPT(1));
  /* TODO
  uv_fs_readdir
  uv_fs_stat
  uv_fs_fstat
  uv_fs_rename
  uv_fs_fsync
  uv_fs_fdatasync
  uv_fs_ftruncate
  uv_fs_sendfile
  uv_fs_chmod
  uv_fs_utime
  uv_fs_futime
  uv_fs_lstat
  uv_fs_link
  uv_fs_symlink
  uv_fs_readlink
  uv_fs_fchmod
  uv_fs_chown
  uv_fs_fchown
  uv_fs_poll_init
  uv_fs_poll_start
  uv_fs_poll_stop
  */
  mrb_gc_arena_restore(mrb, ai);
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
