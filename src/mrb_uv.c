#define _GNU_SOURCE
#include <errno.h>
#include <memory.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include <uv.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#define PATH_MAX MAX_PATH
#endif

extern char **environ;

#define OBJECT_GET(mrb, instance, name) \
  mrb_iv_get(mrb, instance, mrb_intern(mrb, name))

#define OBJECT_SET(mrb, instance, name, value) \
  mrb_iv_set(mrb, instance, mrb_intern(mrb, name), value)

#define OBJECT_REMOVE(mrb, instance, name) \
  mrb_iv_remove(mrb, instance, mrb_intern(mrb, name))

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
    uv_signal_t signal;
    uv_file fs;
    uv_fs_poll_t fs_poll;
    uv_tty_t tty;
    uv_process_t process;
    uv_thread_t thread;
    uv_barrier_t barrier;
  } any;
  mrb_value instance;
  uv_loop_t* loop;
  mrb_state* mrb;
} mrb_uv_context;

static mrb_uv_context*
uv_context_alloc(mrb_state* mrb)
{
  mrb_uv_context* context = (mrb_uv_context*) malloc(sizeof(mrb_uv_context));
  if (!context) return NULL;
  memset(context, 0, sizeof(mrb_uv_context));
  context->loop = uv_default_loop();
  context->mrb = mrb;
  return context;
}

static void
uv_context_free(mrb_state *mrb, void *p)
{
  mrb_uv_context* context = (mrb_uv_context*) p;
  if (context) {
    OBJECT_REMOVE(mrb, context->instance, "read_cb");
    OBJECT_REMOVE(mrb, context->instance, "write_cb");
    OBJECT_REMOVE(mrb, context->instance, "context");
    context->instance = mrb_nil_value();
    context->mrb = NULL;
    context->loop = NULL;
  }
  free(p);
}

static const struct mrb_data_type uv_context_type = {
  "uv_context", uv_context_free,
};

/*********************************************************
 * main
 *********************************************************/
static mrb_value
mrb_uv_gc(mrb_state *mrb, mrb_value self)
{
  int ai = mrb_gc_arena_save(mrb);
  struct RClass* _class_uv = mrb_class_get(mrb, "UV");
  mrb_value uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "$GC"));
  int i, l = RARRAY_LEN(uv_gc_table);
  for (i = 0; i < l; i++) {
    mrb_value obj = mrb_ary_entry(uv_gc_table, i);
    mrb_value ctx  = mrb_iv_get(mrb, obj, mrb_intern(mrb, "context"));
    if (!mrb_nil_p(ctx)) {
      mrb_uv_context* context = NULL;
      Data_Get_Struct(mrb, ctx, &uv_context_type, context);
      if (!context || context->mrb == NULL) {
        mrb_funcall(mrb, uv_gc_table, "delete_at", 1, mrb_fixnum_value(i));
        i--;
        l--;
      }
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_run(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_mode = UV_RUN_DEFAULT;
  mrb_get_args(mrb, "|i", &arg_mode);
  return mrb_fixnum_value(uv_run(uv_default_loop(), arg_mode));
}

/*
 * TODO: need to UV::Once object to avoid gc.
 */
/*
static void
_uv_once_cb() {
  mrb_value proc = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "$ONCE"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_once(mrb_state *mrb, mrb_value self)
{
  mrb_value b = mrb_nil_value();
  mrb_get_args(mrb, "&", &b);
  uv_once_t guard;
  struct RClass* _class_uv = mrb_class_get(mrb, "UV");
  mrb_define_const(mrb, _class_uv, "$ONCE", b);
  uv_once(&guard, _uv_once_cb);
  return mrb_nil_value();
}
*/

static void
_uv_close_cb(uv_handle_t* handle)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "close_cb"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_close_cb close_cb = _uv_close_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (!uv_is_active(&context->any.handle)) return mrb_nil_value();

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    close_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "close_cb"), b);

  uv_close(&context->any.handle, close_cb);
  return mrb_nil_value();
}

static void
_uv_shutdown_cb(uv_shutdown_t* req, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "shutdown_cb"));
  mrb_value args[1];
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_shutdown_cb shutdown_cb = _uv_shutdown_cb;
  uv_shutdown_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    shutdown_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "shutdown_cb"), b);

  req = (uv_shutdown_t*) malloc(sizeof(uv_shutdown_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_shutdown_t));
  req->data = context;
  uv_shutdown(req, &context->any.stream, shutdown_cb);
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
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "read_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    if (nread == -1) {
      args[0] = mrb_nil_value();
      mrb_yield_argv(mrb, proc, 1, args);
    } else if (nread == 0) {
      uv_close(&context->any.handle, NULL);
    } else {
      int ai = mrb_gc_arena_save(mrb);
      args[0] = mrb_str_new(mrb, buf.base, nread);
      mrb_gc_arena_restore(mrb, ai);
      mrb_yield_argv(mrb, proc, 1, args);
      free(buf.base);
    }
  }
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_read_cb read_cb = _uv_read_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    read_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "read_cb"), b);

  err = uv_read_start(&context->any.stream, _uv_alloc_cb, read_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_read_stop(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_read_stop(&context->any.stream);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static void
_uv_write_cb(uv_write_t* req, int status)
{
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "write_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    mrb_iv_set(mrb, context->instance, mrb_intern(mrb, "write_cb"), mrb_nil_value());
    args[0] = mrb_fixnum_value(status);
    mrb_yield_argv(mrb, proc, 1, args);
  }
  free(req);
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_data = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_write_cb write_cb = _uv_write_cb;
  uv_buf_t buf;
  uv_write_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&S", &b, &arg_data);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (mrb_nil_p(b)) {
    write_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "write_cb"), b);

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  req = (uv_write_t*) malloc(sizeof(uv_write_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_write_t));
  req->data = context;
  err = uv_write(req, &context->any.stream, &buf, 1, write_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static void
_uv_connection_cb(uv_stream_t* handle, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "connection_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "connect_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
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
 * UV::Loop
 *********************************************************/
static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_context* context = NULL;

  struct RClass* _class_uv = mrb_class_get(mrb, "UV");
  struct RClass* _class_uv_loop = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Loop")));
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_loop);

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = c;
  context->loop = uv_default_loop();
  mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_context* context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
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
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_int arg_mode = UV_RUN_DEFAULT;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "|i", &arg_mode);
  err = uv_run(uv_default_loop(), arg_mode);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
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
 * UV::Timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  int err;
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_timer_init(loop, &context->any.timer);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.timer.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_timer_again(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_timer_again(&context->any.timer);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static void
_uv_timer_cb(uv_timer_t* timer, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) timer->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "timer_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_timeout = 0, arg_repeat = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_timer_cb timer_cb = _uv_timer_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&ii", &b, &arg_timeout, &arg_repeat);
  if (mrb_nil_p(b)) {
    timer_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "timer_cb"), b);

  err = uv_timer_start(&context->any.timer, timer_cb,
      arg_timeout, arg_repeat);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_timer_stop(&context->any.timer);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::Idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  int err;
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_idle_init(loop, &context->any.idle);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
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
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) idle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "idle_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_idle_cb idle_cb = _uv_idle_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    idle_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "idle_cb"), b);
  uv_idle_init(uv_default_loop(), &context->any.idle);

  err = uv_idle_start(&context->any.idle, idle_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_idle_stop(&context->any.idle);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::Async
 *********************************************************/
static void
_uv_async_cb(uv_async_t* async, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) async->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "async_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_async_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;
  mrb_value b = mrb_nil_value();
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  if (mrb_nil_p(b)) {
    async_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "async_cb"), b);

  err = uv_async_init(loop, &context->any.async, async_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
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
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_async_send(&context->any.async);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::Prepare
 *********************************************************/
static void
_uv_prepare_cb(uv_prepare_t* prepare, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) prepare->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "prepare_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_prepare_init(mrb_state *mrb, mrb_value self)
{
  int err;
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_prepare_init(loop, &context->any.prepare);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
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
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_prepare_cb prepare_cb = _uv_prepare_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    prepare_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "prepare_cb"), b);

  err = uv_prepare_start(&context->any.prepare, prepare_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_prepare_stop(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_prepare_stop(&context->any.prepare);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::Mutex
 *********************************************************/
static mrb_value
mrb_uv_mutex_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_uv_context* context = NULL;
  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = uv_default_loop();
  err = uv_mutex_init(&context->any.mutex);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
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
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_nil_value());
  return mrb_nil_value();
}

/*********************************************************
 * UV::Ip4Addr
 *********************************************************/
static void
uv_ip4addr_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_ip4addr_type = {
  "uv_ip4addr", uv_ip4addr_free,
};

/* NOTE: this type is internally used for instances where a
 * sockaddr is owned by libuv (such as during callbacks),
 * therefore we don't want mruby to free the pointer during
 * garbage collection */
static const struct mrb_data_type uv_ip4addr_nofree_type = {
  "uv_ip4addr_nofree", NULL,
};

static mrb_value
mrb_uv_ip4_addr(mrb_state *mrb, mrb_value self)
{
  int argc;
  mrb_value *argv;
  struct RClass* _class_uv;
  struct RClass* _class_uv_ip4addr;
  mrb_get_args(mrb, "*", &argv, &argc);
  _class_uv = mrb_class_get(mrb, "UV");
  _class_uv_ip4addr = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip4Addr")));
  return mrb_class_new_instance(mrb, argc, argv, _class_uv_ip4addr);
}

static mrb_value
mrb_uv_ip4addr_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_host = mrb_nil_value(), arg_port = mrb_nil_value();
  struct sockaddr_in vaddr;
  struct sockaddr_in *addr = NULL, *paddr = NULL;

  mrb_get_args(mrb, "o|o", &arg_host, &arg_port);
  if (mrb_type(arg_host) == MRB_TT_STRING && !mrb_nil_p(arg_port) && mrb_fixnum_p(arg_port)) {
    vaddr = uv_ip4_addr((const char*) RSTRING_PTR(arg_host), mrb_fixnum(arg_port));
    addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    memcpy(addr, &vaddr, sizeof(struct sockaddr_in));
  } else if (mrb_type(arg_host) == MRB_TT_DATA) {
    if (DATA_TYPE(arg_host) == &uv_ip4addr_nofree_type) {
      paddr = (struct sockaddr_in *) DATA_PTR(arg_host);
    }
    else {
      Data_Get_Struct(mrb, arg_host, &uv_ip4addr_type, paddr);
    }
    addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    memcpy(addr, paddr, sizeof(struct sockaddr_in));
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_ip4addr_type, (void*) addr)));
  return self;
}

static mrb_value
mrb_uv_ip4addr_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value str = mrb_funcall(mrb, self, "sin_addr", 0, NULL);
  mrb_str_cat2(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_funcall(mrb, self, "sin_port", 0, NULL));
  return str;
}

static mrb_value
mrb_uv_ip4addr_sin_addr(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_addr;
  struct sockaddr_in* addr = NULL;
  char name[256];

  value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  if (!addr) {
    return mrb_nil_value();
  }
  err = uv_ip4_name(addr, name, sizeof(name));
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_str_new(mrb, name, strlen(name));
}

static mrb_value
mrb_uv_ip4addr_sin_port(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr;
  struct sockaddr_in* addr = NULL;
  value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  return mrb_fixnum_value(htons(addr->sin_port));
}

/*********************************************************
 * UV::Ip6Addr
 *********************************************************/
static void
uv_ip6addr_free(mrb_state *mrb, void *p)
{
  free(p);
}

static const struct mrb_data_type uv_ip6addr_type = {
  "uv_ip6addr", uv_ip6addr_free,
};

/* NOTE: this type is internally used for instances where a
 * sockaddr is owned by libuv (such as during callbacks),
 * therefore we don't want mruby to free the pointer during
 * garbage collection */
static const struct mrb_data_type uv_ip6addr_nofree_type = {
  "uv_ip6addr_nofree", NULL,
};

static mrb_value
mrb_uv_ip6_addr(mrb_state *mrb, mrb_value self)
{
  int argc;
  mrb_value *argv;
  struct RClass* _class_uv;
  struct RClass* _class_uv_ip6addr;
  mrb_get_args(mrb, "*", &argv, &argc);
  _class_uv = mrb_class_get(mrb, "UV");
  _class_uv_ip6addr = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip6Addr")));
  return mrb_class_new_instance(mrb, argc, argv, _class_uv_ip6addr);
}

static mrb_value
mrb_uv_ip6addr_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_host = mrb_nil_value(), arg_port = mrb_nil_value();
  struct sockaddr_in6 vaddr;
  struct sockaddr_in6 *addr = NULL, *paddr = NULL;

  mrb_get_args(mrb, "o|o", &arg_host, &arg_port);
  if (mrb_type(arg_host) == MRB_TT_STRING && !mrb_nil_p(arg_port) && mrb_fixnum_p(arg_port)) {
    vaddr = uv_ip6_addr((const char*) RSTRING_PTR(arg_host), mrb_fixnum(arg_port));
    addr = (struct sockaddr_in6*) malloc(sizeof(struct sockaddr_in6));
    memcpy(addr, &vaddr, sizeof(struct sockaddr_in6));
  } else if (mrb_type(arg_host) == MRB_TT_DATA) {
    if (DATA_TYPE(arg_host) == &uv_ip6addr_nofree_type) {
      paddr = (struct sockaddr_in6 *) DATA_PTR(arg_host);
    }
    else {
      Data_Get_Struct(mrb, arg_host, &uv_ip6addr_type, paddr);
    }
    addr = (struct sockaddr_in6*) malloc(sizeof(struct sockaddr_in6));
    memcpy(addr, paddr, sizeof(struct sockaddr_in6));
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_ip6addr_type, (void*) addr)));
  return self;
}

static mrb_value
mrb_uv_ip6addr_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value str = mrb_funcall(mrb, self, "sin_addr", 0, NULL);
  mrb_str_cat2(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_funcall(mrb, self, "sin_port", 0, NULL));
  return str;
}

static mrb_value
mrb_uv_ip6addr_sin_addr(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_addr;
  struct sockaddr_in6* addr = NULL;
  char name[256];

  value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  if (!addr) {
    return mrb_nil_value();
  }
  err = uv_ip6_name(addr, name, sizeof(name));
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_str_new(mrb, name, strlen(name));
}

static mrb_value
mrb_uv_ip6addr_sin_port(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr;
  struct sockaddr_in6* addr = NULL;
  value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  return mrb_fixnum_value(htons(addr->sin6_port));
}

/*********************************************************
 * UV::Addrinfo
 *********************************************************/
typedef struct {
  mrb_state* mrb;
  struct addrinfo* addr;
  mrb_value proc;
} mrb_uv_addrinfo;

static void
uv_addrinfo_free(mrb_state *mrb, void *p)
{
  mrb_uv_addrinfo* addr = (mrb_uv_addrinfo*) p;
  uv_freeaddrinfo(addr->addr);
  free(p);
}

static const struct mrb_data_type uv_addrinfo_type = {
  "uv_addrinfo", uv_addrinfo_free,
};

static void
_uv_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
  mrb_value args[2];
  mrb_uv_addrinfo* addr = (mrb_uv_addrinfo*) req->data;
  mrb_state* mrb = addr->mrb;

  mrb_value c = mrb_nil_value();
  if (status != -1) {
    struct RClass* _class_uv = mrb_class_get(mrb, "UV");
    struct RClass* _class_uv_addrinfo = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Addrinfo")));
    c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_addrinfo);
    mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
      Data_Wrap_Struct(mrb, mrb->object_class,
      &uv_addrinfo_type, (void*) res)));
  }

  args[0] = mrb_fixnum_value(status);
  args[1] = c;
  mrb_yield_argv(mrb, addr->proc, 2, args);
}

static mrb_value
mrb_uv_getaddrinfo(mrb_state *mrb, mrb_value self)
{
  mrb_value node, service; 
  mrb_value b = mrb_nil_value();
  uv_getaddrinfo_cb getaddrinfo_cb = _uv_getaddrinfo_cb;
  struct addrinfo hint = {0};
  mrb_uv_addrinfo* addr;
  uv_getaddrinfo_t* req;
  int ret;

  mrb_get_args(mrb, "SS|o&", &node, &service, &hint, &b);

  addr = (mrb_uv_addrinfo*) malloc(sizeof(mrb_uv_addrinfo));
  if (!addr) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(addr, 0, sizeof(mrb_uv_addrinfo));
  addr->mrb = mrb;
  addr->proc = b;

  if (mrb_nil_p(b)) {
    getaddrinfo_cb = NULL;
  }

  req = (uv_getaddrinfo_t*) malloc(sizeof(uv_getaddrinfo_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_getaddrinfo_t));
  req->data = addr;
  ret = uv_getaddrinfo(
    uv_default_loop(),
    req,
    getaddrinfo_cb,
    RSTRING_PTR(node),
    RSTRING_PTR(service),
    &hint);
  return mrb_fixnum_value(ret);
}

static mrb_value
mrb_uv_addrinfo_flags(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->ai_flags);
}

static mrb_value
mrb_uv_addrinfo_family(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->ai_family);
}

static mrb_value
mrb_uv_addrinfo_socktype(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->ai_socktype);
}

static mrb_value
mrb_uv_addrinfo_protocol(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->ai_protocol);
}

static mrb_value
mrb_uv_addrinfo_addr(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  struct RClass* _class_uv;
  mrb_value c = mrb_nil_value();
  mrb_value args[1];

  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);

  _class_uv = mrb_class_get(mrb, "UV");

  switch (addr->ai_family) {
  case AF_INET:
    {
      struct RClass* _class_uv_ip4addr = mrb_class_ptr(mrb_const_get(
          mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip4Addr")));
      args[0] = mrb_obj_value(
        Data_Wrap_Struct(mrb, mrb->object_class,
        &uv_ip4addr_type, (void*) addr->ai_addr));
      c = mrb_class_new_instance(mrb, 1, args, _class_uv_ip4addr);
    }
    break;
  case AF_INET6:
    {
      struct RClass* _class_uv_ip6addr = mrb_class_ptr(mrb_const_get(
          mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip6Addr")));
      args[0] = mrb_obj_value(
        Data_Wrap_Struct(mrb, mrb->object_class,
        &uv_ip6addr_type, (void*) addr->ai_addr));
      c = mrb_class_new_instance(mrb, 1, args, _class_uv_ip6addr);
    }
    break;
  }
  return c;
}

static mrb_value
mrb_uv_addrinfo_canonname(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);
  return mrb_str_new_cstr(mrb,
    addr->ai_canonname ? addr->ai_canonname : "");
}

static mrb_value
mrb_uv_addrinfo_next(mrb_state *mrb, mrb_value self)
{
  mrb_value value_addr = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  struct addrinfo* addr = NULL;
  Data_Get_Struct(mrb, value_addr, &uv_addrinfo_type, addr);

  if (addr->ai_next) {
    struct RClass* _class_uv = mrb_class_get(mrb, "UV");
    struct RClass* _class_uv_ip4addr = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Addrinfo")));

    mrb_value c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_ip4addr);
    mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
      Data_Wrap_Struct(mrb, mrb->object_class,
      &uv_addrinfo_type, (void*) addr->ai_next)));
    return c;
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::TCP
 *********************************************************/
static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  int err;
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_tcp_init(loop, &(context->any.tcp));
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.tcp.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_addr;
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_connect_cb connect_cb = _uv_connect_cb;
  struct sockaddr_storage* addr = NULL;
  uv_connect_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&o", &b, &arg_addr);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  if (version == 4) {
    Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  }
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (mrb_nil_p(b)) {
    connect_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), b);

  req = (uv_connect_t*) malloc(sizeof(uv_connect_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_connect_t));
  req->data = context;
  if (version == 4) {
    err = uv_tcp_connect(req, &context->any.tcp, *((struct sockaddr_in *) addr), connect_cb);
  }
  else {
    err = uv_tcp_connect6(req, &context->any.tcp, *((struct sockaddr_in6 *) addr), connect_cb);
  }
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_connect4(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_tcp_connect(mrb, self, 4);
}

static mrb_value
mrb_uv_tcp_connect6(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_tcp_connect(mrb, self, 6);
}

static mrb_value
mrb_uv_tcp_bind(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_addr = mrb_nil_value();
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_storage* addr = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "o", &arg_addr);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  if (version == 4) {
    Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  }
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (version == 4) {
    err = uv_tcp_bind(&context->any.tcp, *((struct sockaddr_in *) addr));
  }
  else {
    err = uv_tcp_bind6(&context->any.tcp, *((struct sockaddr_in6 *) addr));
  }
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_bind4(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_tcp_bind(mrb, self, 4);
}

static mrb_value
mrb_uv_tcp_bind6(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_tcp_bind(mrb, self, 6);
}

static mrb_value
mrb_uv_tcp_listen(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_backlog = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_connection_cb connection_cb = _uv_connection_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (mrb_nil_p(b)) {
    connection_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b);

  err = uv_listen((uv_stream_t*) &context->any.tcp, arg_backlog, connection_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_accept(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value c, value_context, value_new_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* new_context = NULL;
  struct RClass* _class_uv;
  struct RClass* _class_uv_tcp;
  int ai;
  mrb_value uv_gc_table;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  _class_uv = mrb_class_get(mrb, "UV");
  _class_uv_tcp = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "TCP")));
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_tcp);

  value_new_context = mrb_iv_get(mrb, c, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_new_context, &uv_context_type, new_context);

  new_context->instance = c;
  new_context->loop = context->loop;

  err = uv_accept((uv_stream_t*) &context->any.tcp, (uv_stream_t*) &new_context->any.tcp);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }

  ai = mrb_gc_arena_save(mrb);
  uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "$GC"));
  mrb_ary_push(mrb, uv_gc_table, c);
  mrb_gc_arena_restore(mrb, ai);
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
  mrb_int arg_simultaneous_accepts;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_simultaneous_accepts);
  uv_tcp_simultaneous_accepts(&context->any.tcp, arg_simultaneous_accepts);
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
  mrb_int arg_keepalive, arg_delay;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "ii", &arg_keepalive, &arg_delay);
  uv_tcp_keepalive(&context->any.tcp, arg_keepalive, arg_delay);
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
  mrb_int arg_nodelay;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_nodelay);
  uv_tcp_nodelay(&context->any.tcp, arg_nodelay);
  return mrb_nil_value();
}

/*********************************************************
 * UV::UDP
 *********************************************************/
static mrb_value
mrb_uv_udp_init(mrb_state *mrb, mrb_value self)
{
  int err;
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

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_udp_init(loop, &context->any.udp);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.udp.data = context;

  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_udp_bind(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_addr = mrb_nil_value(), arg_flags = mrb_nil_value();
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_storage* addr = NULL;
  int flags = 0;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "o|o", &arg_addr, &arg_flags);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (!mrb_nil_p(arg_flags)) {
    if (mrb_fixnum_p(arg_flags))
      flags = mrb_fixnum(arg_flags);
    else
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context"));
  if (version == 4) {
    Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  }
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (version == 4) {
    err = uv_udp_bind(&context->any.udp, *((struct sockaddr_in *) addr), flags);
  }
  else {
    err = uv_udp_bind6(&context->any.udp, *((struct sockaddr_in6 *) addr), flags);
  }
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_bind4(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_udp_bind(mrb, self, 4);
}

static mrb_value
mrb_uv_udp_bind6(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_udp_bind(mrb, self, 6);
}

static void
_uv_udp_send_cb(uv_udp_send_t* req, int status)
{
  mrb_value args[1];
  mrb_uv_context* context = (mrb_uv_context*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "udp_send_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 0, args);
}

static mrb_value
mrb_uv_udp_send(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_data = mrb_nil_value(), arg_addr = mrb_nil_value();
  mrb_value value_context, value_addr;
  mrb_uv_context* context = NULL;
  struct sockaddr_storage* addr = NULL;
  mrb_value b = mrb_nil_value();
  uv_udp_send_cb udp_send_cb = _uv_udp_send_cb;
  uv_buf_t buf;
  uv_udp_send_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&So", &b, &arg_data, &arg_addr);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  value_addr = mrb_iv_get(mrb, arg_addr, mrb_intern(mrb, "context")); 
  if (version == 4) {
    Data_Get_Struct(mrb, value_addr, &uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, value_addr, &uv_ip6addr_type, addr);
  }
  if (!addr) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (mrb_nil_p(b)) {
    udp_send_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "udp_send_cb"), b);

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  req = (uv_udp_send_t*) malloc(sizeof(uv_udp_send_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_udp_send_t));
  req->data = context;

  if (version == 4) {
    err = uv_udp_send(req, &context->any.udp, &buf, 1, *((struct sockaddr_in *) addr), udp_send_cb);
  }
  else {
    err = uv_udp_send6(req, &context->any.udp, &buf, 1, *((struct sockaddr_in6 *) addr), udp_send_cb);
  }
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_send4(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_udp_send(mrb, self, 4);
}

static mrb_value
mrb_uv_udp_send6(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_udp_send(mrb, self, 6);
}

static void
_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "udp_recv_cb"));
  mrb_value args[3];
  int ai = mrb_gc_arena_save(mrb);
  if (addr && nread != -1) {
    struct RClass* _class_uv;
    struct RClass* _class_uv_ipaddr = NULL;
    struct RData* data = NULL;
    mrb_value value_data, value_addr = mrb_nil_value();

    _class_uv = mrb_class_get(mrb, "UV");
    switch (addr->sa_family) {
      case AF_INET:
        /* IPv4 */
        _class_uv_ipaddr = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip4Addr")));
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &uv_ip4addr_nofree_type, (void *) addr);
        break;
      case AF_INET6:
        /* IPv6 */
        _class_uv_ipaddr = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Ip6Addr")));
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &uv_ip6addr_nofree_type, (void *) addr);
        break;

      default:
        /* Non-IP */
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
        break;
    }
    value_data = mrb_obj_value((void *) data);
    value_addr = mrb_class_new_instance(mrb, 1, &value_data, _class_uv_ipaddr);
    args[0] = mrb_str_new(mrb, buf.base, nread);
    args[1] = value_addr;
  } else {
    args[0] = mrb_nil_value();
    args[1] = mrb_nil_value();
  }
  mrb_gc_arena_restore(mrb, ai);
  args[2] = mrb_fixnum_value(flags);
  mrb_yield_argv(mrb, proc, 3, args);
}

static mrb_value
mrb_uv_udp_recv_start(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_udp_recv_cb udp_recv_cb = _uv_udp_recv_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    udp_recv_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "udp_recv_cb"), b);

  err = uv_udp_recv_start(&context->any.udp, _uv_alloc_cb, udp_recv_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_recv_stop(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_udp_recv_stop(&context->any.udp);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::Pipe
 *********************************************************/
static mrb_value
mrb_uv_pipe_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_loop = mrb_nil_value(), arg_ipc = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;
  int ipc = 0;

  mrb_get_args(mrb, "o|o", &arg_ipc, &arg_loop);
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
    if (mrb_fixnum_p(arg_ipc))
      ipc = mrb_fixnum(arg_ipc);
    else
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_pipe_init(loop, &context->any.pipe, ipc);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.pipe.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_pipe_open(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_file = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_file);
  err = uv_pipe_open(&context->any.pipe, arg_file);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_name;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_connect_cb connect_cb = _uv_connect_cb;
  char* name = NULL;
  uv_connect_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&S", &b, &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  if (mrb_nil_p(b)) {
    connect_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connect_cb"), b);

  req = (uv_connect_t*) malloc(sizeof(uv_connect_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_connect_t));
  req->data = context;
  uv_pipe_connect(req, &context->any.pipe, name, connect_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_bind(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_name;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  char* name = "";

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "S", &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  err = uv_pipe_bind(&context->any.pipe, name ? name : "");
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_listen(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_backlog;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_connection_cb connection_cb = _uv_connection_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (mrb_nil_p(b)) {
    connection_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "connection_cb"), b);

  err = uv_listen((uv_stream_t*) &context->any.pipe, arg_backlog, connection_cb);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_accept(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value c, value_context, value_new_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* new_context = NULL;
  mrb_value args[1];
  struct RClass* _class_uv;
  struct RClass* _class_uv_pipe;
  int ai;
  mrb_value uv_gc_table;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  args[0] = mrb_fixnum_value(0);
  _class_uv = mrb_class_get(mrb, "UV");
  _class_uv_pipe = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "Pipe")));
  c = mrb_class_new_instance(mrb, 1, args, _class_uv_pipe);

  value_new_context = mrb_iv_get(mrb, c, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_new_context, &uv_context_type, new_context);
  if (!new_context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  new_context->instance = c;
  new_context->loop = context->loop;

  err = uv_accept((uv_stream_t*) &context->any.pipe, (uv_stream_t*) &new_context->any.pipe);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }

  ai = mrb_gc_arena_save(mrb);
  uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "$GC"));
  mrb_ary_push(mrb, uv_gc_table, c);
  mrb_gc_arena_restore(mrb, ai);
  return c;
}


static mrb_value
mrb_uv_pipe_pending_instances(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_count = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "i", &arg_count);
  uv_pipe_pending_instances(&context->any.pipe, arg_count);
  return mrb_nil_value();
}
/*********************************************************
 * UV::FS
 *********************************************************/
static void
_uv_fs_open_cb(uv_fs_t* req)
{
  mrb_uv_context* context = (mrb_uv_context*) req->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (req->result == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(req->result));
  }
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "fs_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    context->any.fs = req->result;
    args[0] = mrb_fixnum_value(req->result);
    mrb_yield_argv(mrb, proc, 1, args);
  }
  uv_fs_req_cleanup(req);
  free(req);
}

static void
_uv_fs_cb(uv_fs_t* req)
{
  mrb_uv_context* context = (mrb_uv_context*) req->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  uv_fs_t close_req;
  if (req->result == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(req->result));
  }
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "fs_cb"));

  switch (req->fs_type) {
  case UV_FS_READDIR:
    if (!mrb_nil_p(proc)) {
       int count;
       char* ptr;
       mrb_value ary;
       mrb_value args[2];
       args[0] = mrb_fixnum_value(req->result);
       count = req->result;
       ptr = req->ptr;
       ary = mrb_ary_new(mrb);
       while (count-- > 0) {
         mrb_ary_push(mrb, ary, mrb_str_new_cstr(mrb, ptr));
         ptr += strlen(ptr) + 1;
       }
       args[1] = ary;
       mrb_yield_argv(mrb, proc, 2, args);
    }
    break;
  default:
    if (req->fs_type == UV_FS_READ && req->result == 0) {
      uv_fs_close(context->loop, &close_req, context->any.fs, NULL);
      goto leave;
    }
    if (!mrb_nil_p(proc)) {
       mrb_value args[1];
       args[0] = mrb_fixnum_value(req->result);
       mrb_yield_argv(mrb, proc, 1, args);
    }
    break;
  }
leave:
  uv_fs_req_cleanup(req);
  free(req);
}

static mrb_value
mrb_uv_fs_fd(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(context->any.fs);
}

static mrb_value
mrb_uv_fs_open(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_filename = mrb_nil_value();
  mrb_int arg_flags, arg_mode;
  uv_fs_cb fs_cb = _uv_fs_open_cb;
  mrb_value b = mrb_nil_value();
  struct RClass* _class_uv;
  struct RClass* _class_uv_fs;
  mrb_value c;
  mrb_uv_context* context;
  uv_fs_t* req;
  int ai;
  mrb_value uv_gc_table;

  mrb_get_args(mrb, "&Sii", &b, &arg_filename, &arg_flags, &arg_mode);

  _class_uv = mrb_class_get(mrb, "UV");
  _class_uv_fs = mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "FS")));
  c = mrb_class_new_instance(mrb, 0, NULL, _class_uv_fs);

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, c, mrb_intern(mrb, "fs_cb"), b);

  context->instance = c;
  context->loop = uv_default_loop();

  mrb_iv_set(mrb, c, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  context->any.fs = uv_fs_open(uv_default_loop(), req, RSTRING_PTR(arg_filename), arg_flags, arg_mode, fs_cb);
  if (context->any.fs < 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(context->any.fs));
  }

  ai = mrb_gc_arena_save(mrb);
  uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern(mrb, "$GC"));
  mrb_ary_push(mrb, uv_gc_table, c);
  mrb_gc_arena_restore(mrb, ai);
  return c;
}

static mrb_value
mrb_uv_fs_close(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  uv_fs_close(uv_default_loop(), req, context->any.fs, fs_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value();
  mrb_int arg_length = -1;
  mrb_int arg_offset = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;
  int r;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&S|i|i", &b, &arg_data, &arg_offset);
  if (mrb_nil_p(arg_data)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  if (arg_length == -1)
    arg_length = RSTRING_LEN(arg_data);
  if (arg_offset < 0)
    arg_offset = 0;
  r = uv_fs_write(uv_default_loop(), req, context->any.fs, RSTRING_PTR(arg_data), arg_length, arg_offset, fs_cb);
  if (r == -1) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(r));
  }
  return mrb_fixnum_value(r);
}

static mrb_value
mrb_uv_fs_read(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_length = BUFSIZ;
  mrb_int arg_offset = 0;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  char* buf;
  size_t len;
  uv_fs_t* req;
  int ai;
  mrb_value str;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&|i|i", &b, &arg_length, &arg_offset);

  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  buf = malloc(arg_length);
  if (!buf) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    free(buf);
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  len = uv_fs_read(uv_default_loop(), req, context->any.fs, buf, arg_length, arg_offset, fs_cb);
  if (len == -1) {
    free(buf);
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(len));
  }
  ai = mrb_gc_arena_save(mrb);
  str = mrb_str_new(mrb, buf, len);
  mrb_gc_arena_restore(mrb, ai);
  free(buf);
  return str;
}

static mrb_value
mrb_uv_fs_unlink(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_unlink(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_mkdir(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path = mrb_nil_value();
  mrb_int arg_mode = 0755;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S|i", &b, &arg_path, &arg_mode);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_mkdir(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_mode, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_rmdir(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_rmdir(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_readdir(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_int arg_flags;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_flags);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_readdir(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_flags, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_stat(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_stat(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_fstat(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_file;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fstat(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_lstat(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_lstat(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_rename(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path, arg_new_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&SS", &b, &arg_path, &arg_new_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_rename(uv_default_loop(), req, RSTRING_PTR(arg_path), RSTRING_PTR(arg_new_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_fsync(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_file;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fsync(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_fdatasync(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_file;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fdatasync(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_ftruncate(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_file, arg_offset;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&ii", &b, &arg_file, &arg_offset);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_ftruncate(uv_default_loop(), req, arg_file, arg_offset, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_sendfile(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_outfd, arg_infd, arg_offset, arg_length;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  // TODO: accept UV::FS object also.
  mrb_get_args(mrb, "&iiii", &b, &arg_infd, &arg_outfd, &arg_offset, &arg_length);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_sendfile(uv_default_loop(), req, arg_infd, arg_outfd, arg_offset, arg_length, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_chmod(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_int arg_mode;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_mode);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_chmod(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_mode, fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_link(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path, arg_new_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_context context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&SS", &b, &arg_path, &arg_new_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_context));
    context.mrb = mrb;
    context.instance = self;
    context.loop = uv_default_loop();
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_cb"), b);

  req = (uv_fs_t*) malloc(sizeof(uv_fs_t));
  if (!req) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_link(uv_default_loop(), req, RSTRING_PTR(arg_path), RSTRING_PTR(arg_new_path), fs_cb);
  if (err != 0) {
    free(req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::FS::Poll
 *********************************************************/
static void
_uv_fs_poll_cb(uv_fs_poll_t* handle, int status, const uv_stat_t* prev, const uv_stat_t* curr)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "fs_poll_cb"));
  if (!mrb_nil_p(proc)) {
     mrb_value args[1];
     args[0] = mrb_fixnum_value(status);
     mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_fs_poll_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
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
    }
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_fs_poll_init(loop, &context->any.fs_poll);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.fs_poll.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_fs_poll_start(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path;
  mrb_int arg_interval;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_poll_cb fs_poll_cb = _uv_fs_poll_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_interval);

  if (mrb_nil_p(b)) {
    fs_poll_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "fs_poll_cb"), b);

  return mrb_fixnum_value(uv_fs_poll_start(&context->any.fs_poll, fs_poll_cb, RSTRING_PTR(arg_path), arg_interval));
}

static mrb_value
mrb_uv_fs_poll_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(uv_fs_poll_stop(&context->any.fs_poll));
}

/*********************************************************
 * UV::Signal
 *********************************************************/
static void
_uv_signal_cb(uv_signal_t* handle, int signum)
{
  mrb_uv_context* context = (mrb_uv_context*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "signal_cb"));
  if (!mrb_nil_p(proc)) {
     mrb_value args[1];
     args[0] = mrb_fixnum_value(signum);
     mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_signal_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_loop = mrb_nil_value();
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
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
    }
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_signal_init(loop, &context->any.signal);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.signal.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_signal_start(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_signal_cb signal_cb = _uv_signal_cb;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  mrb_get_args(mrb, "&i", &b, &arg_signum);

  if (mrb_nil_p(b)) {
    signal_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "signal_cb"), b);

  return mrb_fixnum_value(uv_signal_start(&context->any.signal, signal_cb, arg_signum));
}

static mrb_value
mrb_uv_signal_stop(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(uv_signal_stop(&context->any.signal));
}

/*********************************************************
 * UV::TTY
 *********************************************************/
static mrb_value
mrb_uv_tty_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_loop = mrb_nil_value();
  mrb_int arg_file, arg_readable;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_uv_context* loop_context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "ii|o", &arg_file, &arg_readable, &arg_loop);
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
    }
  } else {
    loop = uv_default_loop();
  }

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = loop;

  err = uv_tty_init(loop, &context->any.tty, arg_file, arg_readable);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  context->any.tty.data = context;
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_tty_set_mode(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_mode;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  mrb_get_args(mrb, "i", &arg_mode);

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(uv_tty_set_mode(&context->any.tty, arg_mode));
}

static mrb_value
mrb_uv_tty_reset_mode(mrb_state *mrb, mrb_value self)
{
  uv_tty_reset_mode();
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tty_get_winsize(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  int width = 0, height = 0;
  mrb_value ary;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  err = uv_tty_get_winsize(&context->any.tty, &width, &height);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  ary = mrb_ary_new(mrb);
  mrb_ary_push(mrb, ary, mrb_fixnum_value(width));
  mrb_ary_push(mrb, ary, mrb_fixnum_value(height));
  return ary;
}

/*********************************************************
 * UV::Process
 *********************************************************/
static void
_uv_exit_cb(uv_process_t* process, int exit_status, int term_signal)
{
  mrb_uv_context* context = (mrb_uv_context*) process->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "exit_cb"));
  if (!mrb_nil_p(proc)) {
     mrb_value args[2];
     args[0] = mrb_fixnum_value(exit_status);
     args[1] = mrb_fixnum_value(term_signal);
     mrb_yield_argv(mrb, proc, 2, args);
  }
}

static mrb_value
mrb_uv_process_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_opt = mrb_nil_value();
  mrb_value arg_file;
  mrb_value arg_args;
  mrb_uv_context* context;

  mrb_get_args(mrb, "H", &arg_opt);
  if (mrb_nil_p(arg_opt)) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  arg_file = mrb_hash_get(mrb, arg_opt, mrb_str_new_cstr(mrb, "file"));
  if (mrb_type(arg_file) != MRB_TT_STRING) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  arg_args = mrb_hash_get(mrb, arg_opt, mrb_str_new_cstr(mrb, "args"));
  if (mrb_type(arg_args) != MRB_TT_ARRAY) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = uv_default_loop();

  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));

  mrb_iv_set(mrb, self, mrb_intern(mrb, "options"), arg_opt);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stdout_pipe"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stderr_pipe"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stdin_pipe"), mrb_nil_value());

  return self;
}

static mrb_value
mrb_uv_process_spawn(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_exit_cb exit_cb = _uv_exit_cb;
  mrb_value options;
  mrb_value arg_file;
  mrb_value arg_args;
  mrb_value stdin_pipe;
  mrb_value stdout_pipe;
  mrb_value stderr_pipe;
  char cwd[PATH_MAX] = {0};
  int i, ret;
  uv_stdio_container_t stdio[3];
  uv_process_options_t opt = {0};
  char** args;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  options = mrb_iv_get(mrb, self, mrb_intern(mrb, "options"));
  arg_file = mrb_hash_get(mrb, options, mrb_str_new_cstr(mrb, "file"));
  arg_args = mrb_hash_get(mrb, options, mrb_str_new_cstr(mrb, "args"));
  stdin_pipe = mrb_iv_get(mrb, self, mrb_intern(mrb, "stdin_pipe"));
  stdout_pipe = mrb_iv_get(mrb, self, mrb_intern(mrb, "stdout_pipe"));
  stderr_pipe = mrb_iv_get(mrb, self, mrb_intern(mrb, "stderr_pipe"));

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    exit_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "exit_cb"), b);

  uv_cwd(cwd, sizeof(cwd));
  args = malloc(sizeof(char*) * (RARRAY_LEN(arg_args)+2));
  args[0] = RSTRING_PTR(arg_file);
  for (i = 0; i < RARRAY_LEN(arg_args); i++) {
    args[i+1] = RSTRING_PTR(mrb_ary_entry(arg_args, i));
  }
  args[i+1] = NULL;

  if (!mrb_nil_p(stdin_pipe)) {
    mrb_value pipe_context = mrb_iv_get(mrb, stdin_pipe, mrb_intern(mrb, "context"));
    mrb_uv_context* pcontext = NULL;
    Data_Get_Struct(mrb, pipe_context, &uv_context_type, pcontext);
    if (!pcontext) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    stdio[0].flags = UV_CREATE_PIPE | UV_READABLE_PIPE;
    stdio[0].data.stream = &pcontext->any.stream;
  } else {
    stdio[0].flags = UV_IGNORE;
  }

  if (!mrb_nil_p(stdout_pipe)) {
    mrb_value pipe_context = mrb_iv_get(mrb, stdout_pipe, mrb_intern(mrb, "context"));
    mrb_uv_context* pcontext = NULL;
    Data_Get_Struct(mrb, pipe_context, &uv_context_type, pcontext);
    if (!pcontext) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    stdio[1].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    stdio[1].data.stream = &pcontext->any.stream;
  } else {
    stdio[1].flags = UV_IGNORE;
  }

  if (!mrb_nil_p(stderr_pipe)) {
    mrb_value pipe_context = mrb_iv_get(mrb, stderr_pipe, mrb_intern(mrb, "context"));
    mrb_uv_context* pcontext = NULL;
    Data_Get_Struct(mrb, pipe_context, &uv_context_type, pcontext);
    if (!pcontext) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
    }
    stdio[2].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    stdio[2].data.stream = &pcontext->any.stream;
  } else {
    stdio[2].flags = UV_IGNORE;
  }

  opt.file = RSTRING_PTR(arg_file);
  opt.args = uv_setup_args(RARRAY_LEN(arg_args)+1, args);
  opt.env = environ;
  opt.cwd = cwd;
  opt.exit_cb = exit_cb;
  opt.stdio_count = 3;
  opt.stdio = stdio;
  opt.uid = 0;
  opt.gid = 0;
  opt.flags = 0;

  ret = uv_spawn(context->loop, &context->any.process, opt);
  free(args);
  if (ret != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(ret));
  }
  context->any.process.data = context;
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_kill(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  mrb_get_args(mrb, "i", &arg_signum);

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  return mrb_fixnum_value(uv_process_kill(&context->any.process, arg_signum));
}

static mrb_value
mrb_uv_process_stdout_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "stdout_pipe"));
}

static mrb_value
mrb_uv_process_stdout_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stdout_pipe"), arg);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_stdin_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "stdin_pipe"));
}

static mrb_value
mrb_uv_process_stdin_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stdin_pipe"), arg);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_stderr_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern(mrb, "stderr_pipe"));
}

static mrb_value
mrb_uv_process_stderr_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "stderr_pipe"), arg);
  return mrb_nil_value();
}

/*********************************************************
 * UV::Thread
 *********************************************************/
static void
_uv_thread_proc(void *arg)
{
  mrb_uv_context* context = (mrb_uv_context*) arg;
  mrb_state* mrb = context->mrb;
  mrb_value proc, thread_arg;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "thread_proc"));
  thread_arg = mrb_iv_get(mrb, context->instance, mrb_intern(mrb, "thread_arg"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    args[0] = thread_arg;
    mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_thread_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value thread_arg = mrb_nil_value();
  mrb_value b = mrb_nil_value();
  mrb_uv_context* context = NULL;

  mrb_get_args(mrb, "&|o", &b, &thread_arg);

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = uv_default_loop();

  mrb_iv_set(mrb, self, mrb_intern(mrb, "thread_proc"), b);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "thread_arg"), thread_arg);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));

  err = uv_thread_create(&context->any.thread, _uv_thread_proc, context);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return self;
}

static mrb_value
mrb_uv_thread_join(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_thread_join(&context->any.thread);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_thread_self(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_thread_self());
}

/*********************************************************
 * UV::Barrier
 *********************************************************/
static mrb_value
mrb_uv_barrier_init(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_count;
  mrb_uv_context* context = NULL;

  mrb_get_args(mrb, "i", &arg_count);

  context = uv_context_alloc(mrb);
  if (!context) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't alloc memory");
  }
  context->instance = self;
  context->loop = uv_default_loop();

  err = uv_barrier_init(&context->any.barrier, arg_count);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_obj_value(
    Data_Wrap_Struct(mrb, mrb->object_class,
    &uv_context_type, (void*) context)));
  return self;
}

static mrb_value
mrb_uv_barrier_wait(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_barrier_wait(&context->any.barrier);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_barrier_destroy(mrb_state *mrb, mrb_value self)
{
  mrb_value value_context;
  mrb_uv_context* context = NULL;

  value_context = mrb_iv_get(mrb, self, mrb_intern(mrb, "context"));
  Data_Get_Struct(mrb, value_context, &uv_context_type, context);
  if (!context) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  uv_barrier_destroy(&context->any.barrier);
  mrb_iv_set(mrb, self, mrb_intern(mrb, "context"), mrb_nil_value());
  return mrb_nil_value();
}
/*********************************************************
 * register
 *********************************************************/

void
mrb_mruby_uv_gem_init(mrb_state* mrb) {
  int ai = mrb_gc_arena_save(mrb);

  struct RClass* _class_uv;
  struct RClass* _class_uv_loop;
  struct RClass* _class_uv_timer;
  struct RClass* _class_uv_idle;
  struct RClass* _class_uv_async;
  struct RClass* _class_uv_prepare;
  struct RClass* _class_uv_addrinfo;
  struct RClass* _class_uv_ip4addr;
  struct RClass* _class_uv_ip6addr;
  struct RClass* _class_uv_tcp;
  struct RClass* _class_uv_udp;
  struct RClass* _class_uv_pipe;
  struct RClass* _class_uv_mutex;
  struct RClass* _class_uv_fs;
  struct RClass* _class_uv_fs_poll;
  struct RClass* _class_uv_signal;
  struct RClass* _class_uv_tty;
  struct RClass* _class_uv_process;
  struct RClass* _class_uv_thread;
  struct RClass* _class_uv_barrier;
  mrb_value uv_gc_table;
  
  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_module_function(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  //mrb_define_module_function(mrb, _class_uv, "once", mrb_uv_once, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "ip6_addr", mrb_uv_ip6_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "getaddrinfo", mrb_uv_getaddrinfo, ARGS_REQ(3));
  mrb_define_module_function(mrb, _class_uv, "gc", mrb_uv_gc, ARGS_NONE());

  // TODO
  //mrb_define_module_function(mrb, _class_uv, "dlopen", mrb_uv_dlopen, ARGS_NONE());
  //mrb_define_module_function(mrb, _class_uv, "dlclose", mrb_uv_dlclose, ARGS_NONE());
  // TODO: uv_dlsym
  // TODO: uv_dlerror

  mrb_define_const(mrb, _class_uv, "UV_RUN_DEFAULT", mrb_fixnum_value(UV_RUN_DEFAULT));
  mrb_define_const(mrb, _class_uv, "UV_RUN_ONCE", mrb_fixnum_value(UV_RUN_ONCE));
  mrb_define_const(mrb, _class_uv, "UV_RUN_NOWAIT", mrb_fixnum_value(UV_RUN_NOWAIT));
#ifdef _WIN32
  mrb_define_const(mrb, _class_uv, "IS_WINDOWS", mrb_true_value());
#else
  mrb_define_const(mrb, _class_uv, "IS_WINDOWS", mrb_false_value());
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_loop = mrb_define_class_under(mrb, _class_uv, "Loop", mrb->object_class);
  mrb_define_method(mrb, _class_uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run", mrb_uv_loop_run, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_delete, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_timer = mrb_define_class_under(mrb, _class_uv, "Timer", mrb->object_class);
  mrb_define_method(mrb, _class_uv_timer, "initialize", mrb_uv_timer_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "again", mrb_uv_timer_again, ARGS_NONE());
  // TODO: uv_timer_set_repeat
  // TODO: uv_timer_get_repeat
  mrb_define_method(mrb, _class_uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_timer, "stop", mrb_uv_timer_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_timer, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_idle = mrb_define_class_under(mrb, _class_uv, "Idle", mrb->object_class);
  mrb_define_method(mrb, _class_uv_idle, "initialize", mrb_uv_idle_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "start", mrb_uv_idle_start, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "stop", mrb_uv_idle_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_idle, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_async = mrb_define_class_under(mrb, _class_uv, "Async", mrb->object_class);
  mrb_define_method(mrb, _class_uv_async, "initialize", mrb_uv_async_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "send", mrb_uv_async_send, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_async, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_prepare = mrb_define_class_under(mrb, _class_uv, "Prepare", mrb->object_class);
  mrb_define_method(mrb, _class_uv_prepare, "initialize", mrb_uv_prepare_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "start", mrb_uv_prepare_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "stop", mrb_uv_prepare_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_addrinfo = mrb_define_class_under(mrb, _class_uv, "Addrinfo", mrb->object_class);
  mrb_define_method(mrb, _class_uv_addrinfo, "flags", mrb_uv_addrinfo_flags, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "family", mrb_uv_addrinfo_family, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "socktype", mrb_uv_addrinfo_socktype, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "protocol", mrb_uv_addrinfo_protocol, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "addr", mrb_uv_addrinfo_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "canonname", mrb_uv_addrinfo_canonname, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "next", mrb_uv_addrinfo_next, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip4addr = mrb_define_class_under(mrb, _class_uv, "Ip4Addr", mrb->object_class);
  mrb_define_method(mrb, _class_uv_ip4addr, "initialize", mrb_uv_ip4addr_init, ARGS_REQ(1) | ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip4addr, "to_s", mrb_uv_ip4addr_to_s, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_addr", mrb_uv_ip4addr_sin_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_port", mrb_uv_ip4addr_sin_port, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip6addr = mrb_define_class_under(mrb, _class_uv, "Ip6Addr", mrb->object_class);
  mrb_define_method(mrb, _class_uv_ip6addr, "initialize", mrb_uv_ip6addr_init, ARGS_REQ(1) | ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip6addr, "to_s", mrb_uv_ip6addr_to_s, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_addr", mrb_uv_ip6addr_sin_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_port", mrb_uv_ip6addr_sin_port, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_tcp = mrb_define_class_under(mrb, _class_uv, "TCP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_NONE());
  // TODO: uv_tcp_open
  // TODO: uv_tcp_getsockname
  // TODO: uv_tcp_getpeername
  // TODO: uv_udp_set_membership
  // TODO: uv_udp_set_multicast_loop
  // TODO: uv_udp_set_multicast_ttl
  // TODO: uv_udp_set_broadcast
  // TODO: uv_udp_set_ttl
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect4, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "connect6", mrb_uv_tcp_connect6, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "write", mrb_uv_write, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "shutdown", mrb_uv_shutdown, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "bind", mrb_uv_tcp_bind4, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "bind6", mrb_uv_tcp_bind6, ARGS_REQ(1));
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

  _class_uv_udp = mrb_define_class_under(mrb, _class_uv, "UDP", mrb->object_class);
  mrb_define_method(mrb, _class_uv_udp, "initialize", mrb_uv_udp_init, ARGS_NONE());
  // TODO: uv_udp_open
  // TODO: uv_udp_getsockname
  mrb_define_method(mrb, _class_uv_udp, "recv_start", mrb_uv_udp_recv_start, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "recv_stop", mrb_uv_udp_recv_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send", mrb_uv_udp_send4, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "send6", mrb_uv_udp_send6, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "bind", mrb_uv_udp_bind4, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "bind6", mrb_uv_udp_bind6, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_pipe = mrb_define_class_under(mrb, _class_uv, "Pipe", mrb->object_class);
  mrb_define_method(mrb, _class_uv_pipe, "initialize", mrb_uv_pipe_init, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "open", mrb_uv_pipe_open, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "connect", mrb_uv_pipe_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_start", mrb_uv_read_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "read_stop", mrb_uv_read_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "write", mrb_uv_write, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "shutdown", mrb_uv_shutdown, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "bind", mrb_uv_pipe_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "listen", mrb_uv_pipe_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "accept", mrb_uv_pipe_accept, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "pending_instances=", mrb_uv_pipe_pending_instances, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_mutex = mrb_define_class_under(mrb, _class_uv, "Mutex", mrb->object_class);
  mrb_define_method(mrb, _class_uv_mutex, "initialize", mrb_uv_mutex_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "lock", mrb_uv_mutex_lock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "trylock", mrb_uv_mutex_trylock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "unlock", mrb_uv_mutex_unlock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "destroy", mrb_uv_mutex_destroy, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_mutex, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_fs = mrb_define_class_under(mrb, _class_uv, "FS", mrb->object_class);
  mrb_define_const(mrb, _class_uv_fs, "O_RDONLY", mrb_fixnum_value(O_RDONLY));
  mrb_define_const(mrb, _class_uv_fs, "O_WRONLY", mrb_fixnum_value(O_WRONLY));
  mrb_define_const(mrb, _class_uv_fs, "O_RDWR", mrb_fixnum_value(O_RDWR));
  mrb_define_const(mrb, _class_uv_fs, "O_CREAT", mrb_fixnum_value(O_CREAT));
  mrb_define_const(mrb, _class_uv_fs, "O_TRUNC", mrb_fixnum_value(O_TRUNC));
  mrb_define_const(mrb, _class_uv_fs, "O_APPEND", mrb_fixnum_value(O_APPEND));
#ifdef O_TEXT
  mrb_define_const(mrb, _class_uv_fs, "O_TEXT", mrb_fixnum_value(O_TEXT));
#endif
#ifdef O_BINARY
  mrb_define_const(mrb, _class_uv_fs, "O_BINARY", mrb_fixnum_value(O_BINARY));
#endif
  mrb_define_const(mrb, _class_uv_fs, "S_IWRITE", mrb_fixnum_value(S_IWRITE));
  mrb_define_const(mrb, _class_uv_fs, "S_IREAD", mrb_fixnum_value(S_IREAD));
  mrb_define_module_function(mrb, _class_uv_fs, "fd", mrb_uv_fs_fd, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv_fs, "open", mrb_uv_fs_open, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs, "write", mrb_uv_fs_write, ARGS_REQ(1) | ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_fs, "read", mrb_uv_fs_read, ARGS_REQ(0) | ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_fs, "close", mrb_uv_fs_close, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv_fs, "unlink", mrb_uv_fs_unlink, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "mkdir", mrb_uv_fs_mkdir, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "rmdir", mrb_uv_fs_rmdir, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "readdir", mrb_uv_fs_readdir, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "stat", mrb_uv_fs_stat, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "fstat", mrb_uv_fs_fstat, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "rename", mrb_uv_fs_rename, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "fsync", mrb_uv_fs_fsync, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "fdatasync", mrb_uv_fs_fdatasync, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "ftruncate", mrb_uv_fs_ftruncate, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "sendfile", mrb_uv_fs_sendfile, ARGS_REQ(4));
  mrb_define_module_function(mrb, _class_uv_fs, "chmod", mrb_uv_fs_chmod, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "lstat", mrb_uv_fs_lstat, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "link", mrb_uv_fs_link, ARGS_REQ(2));
  /* TODO
  UV::FS::Stat object

  uv_fs_event_init
  uv_fs_utime
  uv_fs_futime
  uv_fs_symlink
  uv_fs_readlink
  uv_fs_fchmod
  uv_fs_chown
  uv_fs_fchown
  */
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_fs_poll = mrb_define_class_under(mrb, _class_uv_fs, "Poll", mrb->object_class);
  mrb_define_method(mrb, _class_uv_fs_poll, "initialize", mrb_uv_fs_poll_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_poll, "start", mrb_uv_fs_poll_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs_poll, "stop", mrb_uv_fs_poll_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_poll, "close", mrb_uv_close, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_signal = mrb_define_class_under(mrb, _class_uv, "Signal", mrb->object_class);
  mrb_define_method(mrb, _class_uv_signal, "initialize", mrb_uv_signal_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_signal, "start", mrb_uv_signal_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_signal, "stop", mrb_uv_signal_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_signal, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_const(mrb, _class_uv_signal, "SIGINT", mrb_fixnum_value(SIGINT));
#ifdef SIGPIPE
  mrb_define_const(mrb, _class_uv_signal, "SIGPIPE", mrb_fixnum_value(SIGPIPE));
#endif
#ifdef SIGBREAK
  mrb_define_const(mrb, _class_uv_signal, "SIGBREAK", mrb_fixnum_value(SIGBREAK));
#endif
  mrb_define_const(mrb, _class_uv_signal, "SIGHUP", mrb_fixnum_value(SIGHUP));
  mrb_define_const(mrb, _class_uv_signal, "SIGWINCH", mrb_fixnum_value(SIGWINCH));
  mrb_define_const(mrb, _class_uv_signal, "SIGILL", mrb_fixnum_value(SIGILL));
  mrb_define_const(mrb, _class_uv_signal, "SIGABRT", mrb_fixnum_value(SIGABRT));
  mrb_define_const(mrb, _class_uv_signal, "SIGFPE", mrb_fixnum_value(SIGFPE));
  mrb_define_const(mrb, _class_uv_signal, "SIGSEGV", mrb_fixnum_value(SIGSEGV));
  mrb_define_const(mrb, _class_uv_signal, "SIGTERM", mrb_fixnum_value(SIGTERM));
  mrb_define_const(mrb, _class_uv_signal, "SIGKILL", mrb_fixnum_value(SIGKILL));
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_tty = mrb_define_class_under(mrb, _class_uv, "TTY", mrb->object_class);
  mrb_define_method(mrb, _class_uv_tty, "initialize", mrb_uv_tty_init, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tty, "set_mode", mrb_uv_tty_set_mode, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_tty, "reset_mode", mrb_uv_tty_reset_mode, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tty, "get_winsize", mrb_uv_tty_get_winsize, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tty, "close", mrb_uv_close, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_process = mrb_define_class_under(mrb, _class_uv, "Process", mrb->object_class);
  mrb_define_method(mrb, _class_uv_process, "initialize", mrb_uv_process_init, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "spawn", mrb_uv_process_spawn, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe=", mrb_uv_process_stdout_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe", mrb_uv_process_stdout_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe=", mrb_uv_process_stdin_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe", mrb_uv_process_stdin_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe=", mrb_uv_process_stderr_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe", mrb_uv_process_stderr_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "kill", mrb_uv_process_kill, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "close", mrb_uv_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_thread = mrb_define_class_under(mrb, _class_uv, "Thread", mrb->object_class);
  mrb_define_module_function(mrb, _class_uv_thread, "self", mrb_uv_thread_self, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_thread, "initialize", mrb_uv_thread_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_thread, "join", mrb_uv_thread_join, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_barrier = mrb_define_class_under(mrb, _class_uv, "Barrier", mrb->object_class);
  mrb_define_method(mrb, _class_uv_barrier, "initialize", mrb_uv_barrier_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "wait", mrb_uv_barrier_wait, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "destroy", mrb_uv_barrier_destroy, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  /* TODO
  uv_guess_handle
  uv_poll_init
  uv_poll_init_socket
  uv_poll_start
  uv_poll_stop
  uv_check_init
  uv_check_start
  uv_check_stop
  uv_kill
  uv_queue_work
  uv_cancel
  uv_setup_args
  uv_set_process_title
  uv_get_process_title
  uv_uptime
  uv_cpu_info
  uv_free_cpu_info
  uv_interface_addresses
  uv_free_interface_addresses
  uv_loadavg
  uv_inet_ntop
  uv_inet_pton
  uv_exepath
  uv_cwd
  uv_chdir
  uv_get_free_memory
  uv_get_total_memory
  uv_hrtime
  uv_disable_stdio_inheritance
  uv_rwlock_init
  uv_rwlock_destroy
  uv_rwlock_rdlock
  uv_rwlock_tryrdlock
  uv_rwlock_rdunlock
  uv_rwlock_wrlock
  uv_rwlock_trywrlock
  uv_rwlock_wrunlock
  uv_sem_init
  uv_sem_destroy
  uv_sem_post
  uv_sem_wait
  uv_sem_trywait
  uv_cond_init
  uv_cond_destroy
  uv_cond_signal
  uv_cond_broadcast
  uv_cond_wait
  uv_cond_timedwait
  */

  uv_gc_table = mrb_ary_new(mrb);
  mrb_define_const(mrb, _class_uv, "$GC", uv_gc_table);
}

void
mrb_mruby_uv_gem_final(mrb_state* mrb) {
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
