#include "mruby/uv.h"
#include "mrb_uv.h"


extern char **environ;

static uv_loop_t*
get_loop(mrb_state *mrb, mrb_value v)
{
  if(mrb_nil_p(v)) {
    return uv_default_loop();
  } else {
    return (uv_loop_t*)mrb_uv_get_ptr(mrb, v, &mrb_uv_loop_type);
  }
}

typedef struct {
  mrb_state* mrb;
  mrb_value instance;
  uv_handle_t handle;
} mrb_uv_handle;

static void
mrb_uv_handle_free(mrb_state *mrb, void *p)
{
  mrb_uv_handle* context = (mrb_uv_handle*) p;
  if (context && !uv_is_closing(&context->handle)) {
    uv_close(&context->handle, NULL);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type mrb_uv_handle_type = {
  "uv_handle", mrb_uv_handle_free
};

mrb_uv_handle*
mrb_uv_handle_alloc(mrb_state* mrb, size_t size, mrb_value instance)
{
  mrb_uv_handle* context = (mrb_uv_handle*) mrb_malloc(mrb, sizeof(mrb_uv_handle) + (size - sizeof(uv_handle_t)));
  context->mrb = mrb;
  context->instance = instance;
  context->handle.data = context;
  context->handle.type = UV_UNKNOWN_HANDLE;
  mrb_assert(mrb_type(instance) == MRB_TT_DATA);
  DATA_PTR(instance) = context;
  DATA_TYPE(instance) = &mrb_uv_handle_type;
  return context;
}

static void
_uv_connect_cb(uv_connect_t* req, int status)
{
  mrb_value args[1];
  mrb_uv_handle* context = (mrb_uv_handle*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "connect_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static void
_uv_connection_cb(uv_stream_t* handle, int status)
{
  mrb_value args[1];
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "connection_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static void
_uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
  buf->base = mrb_malloc(((mrb_uv_handle*)handle->data)->mrb, suggested_size);
  buf->len = suggested_size;
}

static void
_uv_close_cb(uv_handle_t* handle)
{
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "close_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_yield_argv(mrb, proc, 0, NULL);
  }
  DATA_PTR(context->instance) = NULL;
  mrb_free(mrb, context);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();

  if (uv_is_closing(&context->handle)) return mrb_nil_value();

  mrb_get_args(mrb, "&", &b);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "close_cb"), b);
  uv_close(&context->handle, mrb_nil_p(b)? NULL : _uv_close_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_is_closing(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_bool_value(uv_is_closing(&ctx->handle));
}

static mrb_value
mrb_uv_is_active(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_bool_value(uv_is_active(&ctx->handle));
}

static mrb_value
mrb_uv_ref(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return uv_ref(&ctx->handle), self;
}

static mrb_value
mrb_uv_unref(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return uv_unref(&ctx->handle), self;
}

static mrb_value
mrb_uv_has_ref(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_bool_value(uv_has_ref(&ctx->handle));
}

/*********************************************************
 * UV::Pipe
 *********************************************************/
static mrb_value
mrb_uv_pipe_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value(), arg_ipc = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;
  int ipc = 0;

  mrb_get_args(mrb, "o|o", &arg_ipc, &arg_loop);
  loop = get_loop(mrb, arg_loop);
  if (!mrb_nil_p(arg_ipc)) {
    if (mrb_fixnum_p(arg_ipc))
      ipc = mrb_fixnum(arg_ipc);
    else
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_pipe_t), self);

  mrb_uv_check_error(mrb, uv_pipe_init(loop, (uv_pipe_t*)&context->handle, ipc));
  return self;
}

static mrb_value
mrb_uv_pipe_open(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_file = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_file);
  mrb_uv_check_error(mrb, uv_pipe_open((uv_pipe_t*)&context->handle, arg_file));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_connect(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_name;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_connect_cb connect_cb = _uv_connect_cb;
  char* name = NULL;
  uv_connect_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  if (mrb_nil_p(b)) {
    connect_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "connect_cb"), b);

  req = (uv_connect_t*) mrb_malloc(mrb, sizeof(uv_connect_t));
  memset(req, 0, sizeof(uv_connect_t));
  req->data = context;
  uv_pipe_connect(req, (uv_pipe_t*)&context->handle, name, connect_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_bind(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_name;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  char* name = "";

  mrb_get_args(mrb, "S", &arg_name);
  if (mrb_nil_p(arg_name) || mrb_type(arg_name) != MRB_TT_STRING) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  name = RSTRING_PTR(arg_name);

  mrb_uv_check_error(mrb, uv_pipe_bind((uv_pipe_t*)&context->handle, name ? name : ""));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_listen(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_backlog;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_connection_cb connection_cb = _uv_connection_cb;

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (mrb_nil_p(b)) {
    connection_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "connection_cb"), b);

  mrb_uv_check_error(mrb, uv_listen((uv_stream_t*) &context->handle, arg_backlog, connection_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_pipe_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_handle* new_context = NULL;
  mrb_value args[1];
  struct RClass* _class_uv;
  struct RClass* _class_uv_pipe;
  int ai;
  mrb_value uv_gc_table;

  args[0] = mrb_fixnum_value(0);
  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_pipe = mrb_class_get_under(mrb, _class_uv, "Pipe");
  c = mrb_obj_new(mrb, _class_uv_pipe, 1, args);

  Data_Get_Struct(mrb, c, &mrb_uv_handle_type, new_context);

  mrb_uv_check_error(mrb, uv_accept((uv_stream_t*) &context->handle, (uv_stream_t*) &new_context->handle));

  ai = mrb_gc_arena_save(mrb);
  uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "$GC"));
  mrb_ary_push(mrb, uv_gc_table, c);
  mrb_gc_arena_restore(mrb, ai);
  return c;
}

static mrb_value
mrb_uv_pipe_pending_instances(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_count = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_count);
  uv_pipe_pending_instances((uv_pipe_t*)&context->handle, arg_count);
  return mrb_nil_value();
}

/*********************************************************
 * UV::TCP
 *********************************************************/
static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_tcp_t), self);

  mrb_uv_check_error(mrb, uv_tcp_init(loop, (uv_tcp_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_addr;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_connect_cb connect_cb = _uv_connect_cb;
  struct sockaddr_storage* addr = NULL;
  uv_connect_t* req;

  mrb_get_args(mrb, "&o", &b, &arg_addr);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (version == 4) {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip6addr_type, addr);
  }

  if (mrb_nil_p(b)) {
    connect_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "connect_cb"), b);

  req = (uv_connect_t*) mrb_malloc(mrb, sizeof(uv_connect_t));
  memset(req, 0, sizeof(uv_connect_t));
  req->data = context;
  err = uv_tcp_connect(req, (uv_tcp_t*)&context->handle, ((const struct sockaddr *) addr), connect_cb);
  if (err != 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
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
  mrb_value arg_addr = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  struct sockaddr_storage* addr = NULL;

  mrb_get_args(mrb, "o", &arg_addr);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (version == 4) {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip6addr_type, addr);
  }

  mrb_uv_check_error(mrb, uv_tcp_bind((uv_tcp_t*)&context->handle, ((const struct sockaddr *) addr), version == 4? 0 : UV_TCP_IPV6ONLY));
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
  mrb_int arg_backlog = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_connection_cb connection_cb = _uv_connection_cb;

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  if (mrb_nil_p(b)) {
    connection_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "connection_cb"), b);

  mrb_uv_check_error(mrb, uv_listen((uv_stream_t*) &context->handle, arg_backlog, connection_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_handle* new_context = NULL;
  struct RClass* _class_uv;
  struct RClass* _class_uv_tcp;
  int ai;
  mrb_value uv_gc_table;

  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_tcp = mrb_class_get_under(mrb, _class_uv, "TCP");
  c = mrb_obj_new(mrb, _class_uv_tcp, 0, NULL);

  Data_Get_Struct(mrb, c, &mrb_uv_handle_type, new_context);

  mrb_uv_check_error(mrb, uv_accept((uv_stream_t*) &context->handle, (uv_stream_t*) &new_context->handle));

  mrb_uv_gc_protect(mrb, c);
  return c;
}

/*
static mrb_value
mrb_uv_tcp_simultaneous_accepts_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "simultaneous_accepts"));
}
*/

static mrb_value
mrb_uv_tcp_simultaneous_accepts_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_simultaneous_accepts;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_simultaneous_accepts);
  uv_tcp_simultaneous_accepts((uv_tcp_t*)&context->handle, arg_simultaneous_accepts);
  return mrb_nil_value();
}

/*
static mrb_value
mrb_uv_tcp_keepalive_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "keepalive"));
}
*/

static mrb_value
mrb_uv_tcp_keepalive_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_keepalive, arg_delay;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "ii", &arg_keepalive, &arg_delay);
  uv_tcp_keepalive((uv_tcp_t*)&context->handle, arg_keepalive, arg_delay);
  return mrb_nil_value();
}

/*
static mrb_value
mrb_uv_tcp_nodelay_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "nodelay"));
}
*/

static mrb_value
mrb_uv_tcp_nodelay_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_nodelay;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_nodelay);
  uv_tcp_nodelay((uv_tcp_t*)&context->handle, arg_nodelay);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_tcp_getpeername(mrb_state *mrb, mrb_value self)
{
  int len;
  struct sockaddr_storage addr;
  struct RClass* _class_uv;
  struct RClass* _class_uv_ipaddr;
  struct RData *data;
  mrb_value value_data, value_result = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  len = sizeof(addr);
  mrb_uv_check_error(mrb, uv_tcp_getpeername((uv_tcp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  switch (addr.ss_family) {
    case AF_INET:
    case AF_INET6:
      _class_uv = mrb_module_get(mrb, "UV");
      if (addr.ss_family == AF_INET) {
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip4addr_nofree_type, (void *) &addr);
      }
      else {
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip6Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip6addr_nofree_type, (void *) &addr);
      }
      value_data = mrb_obj_value((void *) data);
      value_result = mrb_class_new_instance(mrb, 1, &value_data,
          _class_uv_ipaddr);
      break;
  }
  return value_result;
}

static mrb_value
mrb_uv_getsockname(mrb_state *mrb, mrb_value self, int tcp)
{
  int len;
  struct sockaddr_storage addr;
  struct RClass* _class_uv;
  struct RClass* _class_uv_ipaddr;
  struct RData *data;
  mrb_value value_data, value_result = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  len = sizeof(addr);
  if (tcp) {
    mrb_uv_check_error(mrb, uv_tcp_getsockname((uv_tcp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  }
  else {
    mrb_uv_check_error(mrb, uv_udp_getsockname((uv_udp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  }
  switch (addr.ss_family) {
    case AF_INET:
    case AF_INET6:
      _class_uv = mrb_module_get(mrb, "UV");
      if (addr.ss_family == AF_INET) {
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip4addr_nofree_type, (void *) &addr);
      }
      else {
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip6Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip6addr_nofree_type, (void *) &addr);
      }
      value_data = mrb_obj_value((void *) data);
      value_result = mrb_class_new_instance(mrb, 1, &value_data,
          _class_uv_ipaddr);
      break;
  }
  return value_result;
}

static mrb_value
mrb_uv_tcp_getsockname(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_getsockname(mrb, self, 1);
}

/*********************************************************
 * UV::UDP
 *********************************************************/
static mrb_value
mrb_uv_udp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_udp_t), self);

  mrb_uv_check_error(mrb, uv_udp_init(loop, (uv_udp_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_udp_bind(mrb_state *mrb, mrb_value self, int version)
{
  mrb_value arg_addr = mrb_nil_value(), arg_flags = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  struct sockaddr_storage* addr = NULL;
  int flags = 0;

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
  if (version == 4) {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip6addr_type, addr);
  }

  mrb_uv_check_error(mrb, uv_udp_bind((uv_udp_t*)&context->handle, ((const struct sockaddr *) addr), flags));
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
  mrb_uv_handle* context = (mrb_uv_handle*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "udp_send_cb"));
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 0, args);
}

static mrb_value
mrb_uv_udp_send(mrb_state *mrb, mrb_value self, int version)
{
  int err;
  mrb_value arg_data = mrb_nil_value(), arg_addr = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  struct sockaddr_storage* addr = NULL;
  mrb_value b = mrb_nil_value();
  uv_udp_send_cb udp_send_cb = _uv_udp_send_cb;
  uv_buf_t buf;
  uv_udp_send_t* req;

  mrb_get_args(mrb, "&So", &b, &arg_data, &arg_addr);
  if (version != 4 && version != 6) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "(INTERNAL BUG) invalid IP version!");
  }
  if (mrb_nil_p(arg_addr) || strcmp(mrb_obj_classname(mrb, arg_addr), version == 4 ? "UV::Ip4Addr" : "UV::Ip6Addr")) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }

  if (version == 4) {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip4addr_type, addr);
  }
  else {
    Data_Get_Struct(mrb, arg_addr, &mrb_uv_ip6addr_type, addr);
  }

  if (mrb_nil_p(b)) {
    udp_send_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "udp_send_cb"), b);

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  req = (uv_udp_send_t*) mrb_malloc(mrb, sizeof(uv_udp_send_t));
  memset(req, 0, sizeof(uv_udp_send_t));
  req->data = context;

  err = uv_udp_send(req, (uv_udp_t*)&context->handle, &buf, 1, ((const struct sockaddr *) addr), udp_send_cb);
  if (err != 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
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
_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "udp_recv_cb"));
  mrb_value args[3];
  int ai = mrb_gc_arena_save(mrb);
  if (addr && nread >= 0) {
    struct RClass* _class_uv;
    struct RClass* _class_uv_ipaddr = NULL;
    struct RData* data = NULL;
    mrb_value value_data, value_addr = mrb_nil_value();

    _class_uv = mrb_module_get(mrb, "UV");
    switch (addr->sa_family) {
      case AF_INET:
        /* IPv4 */
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip4addr_nofree_type, (void *) addr);
        break;
      case AF_INET6:
        /* IPv6 */
        _class_uv_ipaddr = mrb_class_get_under(mrb, _class_uv, "Ip6Addr");
        data = Data_Wrap_Struct(mrb, mrb->object_class,
            &mrb_uv_ip6addr_nofree_type, (void *) addr);
        break;

      default:
        /* Non-IP */
        mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
        break;
    }
    value_data = mrb_obj_value((void *) data);
    value_addr = mrb_obj_new(mrb, _class_uv_ipaddr, 1, &value_data);
    args[0] = mrb_str_new(mrb, buf->base, nread);
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
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_udp_recv_cb udp_recv_cb = _uv_udp_recv_cb;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    udp_recv_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "udp_recv_cb"), b);

  mrb_uv_check_error(mrb, uv_udp_recv_start((uv_udp_t*)&context->handle, _uv_alloc_cb, udp_recv_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_recv_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_udp_recv_stop((uv_udp_t*)&context->handle));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_udp_getsockname(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_getsockname(mrb, self, 0);
}

/*********************************************************
 * UV::Prepare
 *********************************************************/
static void
_uv_prepare_cb(uv_prepare_t* prepare)
{
  mrb_uv_handle* context = (mrb_uv_handle*) prepare->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "prepare_cb"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_prepare_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_prepare_t), self);

  mrb_uv_check_error(mrb, uv_prepare_init(loop, (uv_prepare_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_prepare_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_prepare_cb prepare_cb = _uv_prepare_cb;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    prepare_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "prepare_cb"), b);

  mrb_uv_check_error(mrb, uv_prepare_start((uv_prepare_t*)&context->handle, prepare_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_prepare_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_prepare_stop((uv_prepare_t*)&context->handle));
  return mrb_nil_value();
}

/*********************************************************
 * UV::Async
 *********************************************************/
static void
_uv_async_cb(uv_async_t* async)
{
  mrb_uv_handle* context = (mrb_uv_handle*) async->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "async_cb"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_async_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;
  mrb_value b = mrb_nil_value();
  uv_async_cb async_cb = _uv_async_cb;

  mrb_get_args(mrb, "&|o", &b, &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_async_t), self);

  if (mrb_nil_p(b)) {
    async_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "async_cb"), b);

  mrb_uv_check_error(mrb, uv_async_init(loop, (uv_async_t*)&context->handle, async_cb));
  return self;
}

static mrb_value
mrb_uv_async_send(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_async_send((uv_async_t*)&context->handle));
  return mrb_nil_value();
}

/*********************************************************
 * UV::Idle
 *********************************************************/
static mrb_value
mrb_uv_idle_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_idle_t), self);

  mrb_uv_check_error(mrb, uv_idle_init(loop, (uv_idle_t*)&context->handle));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle)
{
  mrb_uv_handle* context = (mrb_uv_handle*) idle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "idle_cb"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_idle_cb idle_cb = _uv_idle_cb;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    idle_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "idle_cb"), b);
  uv_idle_init(uv_default_loop(), (uv_idle_t*)&context->handle);

  mrb_uv_check_error(mrb, uv_idle_start((uv_idle_t*)&context->handle, idle_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_idle_stop((uv_idle_t*)&context->handle));
  return mrb_nil_value();
}

/*********************************************************
 * UV::TTY
 *********************************************************/
static mrb_value
mrb_uv_tty_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_int arg_file, arg_readable;
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "ii|o", &arg_file, &arg_readable, &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_tty_t), self);

  mrb_uv_check_error(mrb, uv_tty_init(loop, (uv_tty_t*)&context->handle, arg_file, arg_readable));
  return self;
}

static mrb_value
mrb_uv_tty_set_mode(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_mode;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_mode);

  return mrb_fixnum_value(uv_tty_set_mode((uv_tty_t*)&context->handle, arg_mode));
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
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  int width = 0, height = 0;
  mrb_value ary;

  mrb_uv_check_error(mrb, uv_tty_get_winsize((uv_tty_t*)&context->handle, &width, &height));
  ary = mrb_ary_new(mrb);
  mrb_ary_push(mrb, ary, mrb_fixnum_value(width));
  mrb_ary_push(mrb, ary, mrb_fixnum_value(height));
  return ary;
}

/*********************************************************
 * UV::Process
 *********************************************************/
static void
_uv_exit_cb(uv_process_t* process, int64_t exit_status, int term_signal)
{
  mrb_uv_handle* context = (mrb_uv_handle*) process->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "exit_cb"));
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

  mrb_get_args(mrb, "H", &arg_opt);
  if (mrb_nil_p(arg_opt)) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  arg_file = mrb_hash_get(mrb, arg_opt, mrb_str_new_cstr(mrb, "file"));
  if (mrb_type(arg_file) != MRB_TT_STRING) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  arg_args = mrb_hash_get(mrb, arg_opt, mrb_str_new_cstr(mrb, "args"));
  if (mrb_type(arg_args) != MRB_TT_ARRAY) mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "options"), arg_opt);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stdout_pipe"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stderr_pipe"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stdin_pipe"), mrb_nil_value());

  return self;
}

static mrb_value
mrb_uv_process_spawn(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context;
  mrb_value b = mrb_nil_value();
  uv_exit_cb exit_cb = _uv_exit_cb;
  mrb_value options;
  mrb_value arg_file;
  mrb_value arg_args;
  mrb_value stdin_pipe;
  mrb_value stdout_pipe;
  mrb_value stderr_pipe;
  char cwd[PATH_MAX];
  size_t cwd_size = sizeof(cwd);
  int i, err;
  uv_stdio_container_t stdio[3];
  uv_process_options_t opt = {0};
  char** args;

  options = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "options"));
  arg_file = mrb_hash_get(mrb, options, mrb_str_new_cstr(mrb, "file"));
  arg_args = mrb_hash_get(mrb, options, mrb_str_new_cstr(mrb, "args"));
  stdin_pipe = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdin_pipe"));
  stdout_pipe = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdout_pipe"));
  stderr_pipe = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stderr_pipe"));

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    exit_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "exit_cb"), b);

  uv_cwd(cwd, &cwd_size);
  args = mrb_malloc(mrb, sizeof(char*) * (RARRAY_LEN(arg_args)+2));
  args[0] = RSTRING_PTR(arg_file);
  for (i = 0; i < RARRAY_LEN(arg_args); i++) {
    args[i+1] = RSTRING_PTR(mrb_ary_entry(arg_args, i));
  }
  args[i+1] = NULL;

  if (!mrb_nil_p(stdin_pipe)) {
    mrb_uv_handle* pcontext = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, stdin_pipe, &mrb_uv_handle_type);
    stdio[0].flags = UV_CREATE_PIPE | UV_READABLE_PIPE;
    stdio[0].data.stream = (uv_stream_t*)&pcontext->handle;
  } else {
    stdio[0].flags = UV_IGNORE;
  }

  if (!mrb_nil_p(stdout_pipe)) {
    mrb_uv_handle* pcontext = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, stdout_pipe, &mrb_uv_handle_type);
    stdio[1].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    stdio[1].data.stream = (uv_stream_t*)&pcontext->handle;
  } else {
    stdio[1].flags = UV_IGNORE;
  }

  if (!mrb_nil_p(stderr_pipe)) {
    mrb_uv_handle* pcontext = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, stderr_pipe, &mrb_uv_handle_type);
    stdio[2].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    stdio[2].data.stream = (uv_stream_t*)&pcontext->handle;
  } else {
    stdio[2].flags = UV_IGNORE;
  }

  opt.file = RSTRING_PTR(arg_file);
  opt.args = uv_setup_args(RARRAY_LEN(arg_args), args);
  opt.env = environ;
  opt.cwd = cwd;
  opt.exit_cb = exit_cb;
  opt.stdio_count = 3;
  opt.stdio = stdio;
  opt.uid = 0;
  opt.gid = 0;
  opt.flags = 0;

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_process_t), self);
  err = uv_spawn(uv_default_loop(), (uv_process_t*)&context->handle, &opt);
  mrb_free(mrb, args);
  if (err != 0) {
    mrb_uv_check_error(mrb, err);
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_kill(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_signum);

  return mrb_fixnum_value(uv_process_kill((uv_process_t*)&context->handle, arg_signum));
}

static mrb_value
mrb_uv_process_stdout_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdout_pipe"));
}

static mrb_value
mrb_uv_process_stdout_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stdout_pipe"), arg);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_stdin_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdin_pipe"));
}

static mrb_value
mrb_uv_process_stdin_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stdin_pipe"), arg);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_process_stderr_pipe_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stderr_pipe"));
}

static mrb_value
mrb_uv_process_stderr_pipe_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "stderr_pipe"), arg);
  return mrb_nil_value();
}

/*********************************************************
 * UV::Timer
 *********************************************************/
static mrb_value
mrb_uv_timer_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_timer_t), self);

  mrb_uv_check_error(mrb, uv_timer_init(loop, (uv_timer_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_timer_again(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_timer_again((uv_timer_t*)&context->handle));
  return mrb_nil_value();
}

static void
_uv_timer_cb(uv_timer_t* timer)
{
  mrb_uv_handle* context = (mrb_uv_handle*) timer->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "timer_cb"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_timeout = 0, arg_repeat = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_timer_cb timer_cb = _uv_timer_cb;

  mrb_get_args(mrb, "&ii", &b, &arg_timeout, &arg_repeat);
  if (mrb_nil_p(b)) {
    timer_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "timer_cb"), b);

  mrb_uv_check_error(mrb, uv_timer_start((uv_timer_t*)&context->handle, timer_cb,
                                         arg_timeout, arg_repeat));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_timer_stop((uv_timer_t*)&context->handle));
  return mrb_nil_value();
}

/*********************************************************
 * UV::FS::Poll
 *********************************************************/
static void
_uv_fs_poll_cb(uv_fs_poll_t* handle, int status, const uv_stat_t* prev, const uv_stat_t* curr)
{
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "fs_poll_cb"));
  if (!mrb_nil_p(proc)) {
     mrb_value args[1];
     args[0] = mrb_fixnum_value(status);
     mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_fs_poll_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_fs_poll_t), self);

  mrb_uv_check_error(mrb, uv_fs_poll_init(loop, (uv_fs_poll_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_fs_poll_start(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path;
  mrb_int arg_interval;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_fs_poll_cb fs_poll_cb = _uv_fs_poll_cb;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_interval);

  if (mrb_nil_p(b)) {
    fs_poll_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_poll_cb"), b);

  return mrb_fixnum_value(uv_fs_poll_start((uv_fs_poll_t*)&context->handle, fs_poll_cb, RSTRING_PTR(arg_path), arg_interval));
}

static mrb_value
mrb_uv_fs_poll_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_fs_poll_stop((uv_fs_poll_t*)&context->handle));
}

/*********************************************************
 * UV::Signal
 *********************************************************/
static void
_uv_signal_cb(uv_signal_t* handle, int signum)
{
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "signal_cb"));
  if (!mrb_nil_p(proc)) {
     mrb_value args[1];
     args[0] = mrb_fixnum_value(signum);
     mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_signal_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, arg_loop);

  context = mrb_uv_handle_alloc(mrb, sizeof(uv_signal_t), self);

  mrb_uv_check_error(mrb, uv_signal_init(loop, (uv_signal_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_signal_start(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_signal_cb signal_cb = _uv_signal_cb;

  mrb_get_args(mrb, "&i", &b, &arg_signum);

  if (mrb_nil_p(b)) {
    signal_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "signal_cb"), b);

  return mrb_fixnum_value(uv_signal_start((uv_signal_t*)&context->handle, signal_cb, arg_signum));
}

static mrb_value
mrb_uv_signal_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_signal_stop((uv_signal_t*)&context->handle));
}

static void
_uv_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
  mrb_uv_handle* context = (mrb_uv_handle*) stream->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "read_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    if (nread < 0) {
      args[0] = mrb_nil_value();
      mrb_yield_argv(mrb, proc, 1, args);
    } else if (nread == 0) {
      uv_close(&context->handle, NULL);
    } else {
      int ai = mrb_gc_arena_save(mrb);
      args[0] = mrb_str_new(mrb, buf->base, nread);
      mrb_gc_arena_restore(mrb, ai);
      mrb_yield_argv(mrb, proc, 1, args);
      mrb_free(mrb, buf->base);
    }
  }
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_read_cb read_cb = _uv_read_cb;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    read_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "read_cb"), b);

  mrb_uv_check_error(mrb, uv_read_start((uv_stream_t*)&context->handle, _uv_alloc_cb, read_cb));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_read_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_read_stop((uv_stream_t*)&context->handle));
  return mrb_nil_value();
}

static void
_uv_write_cb(uv_write_t* req, int status)
{
  mrb_uv_handle* context = (mrb_uv_handle*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "write_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    mrb_iv_set(mrb, context->instance, mrb_intern_lit(mrb, "write_cb"), mrb_nil_value());
    args[0] = mrb_fixnum_value(status);
    mrb_yield_argv(mrb, proc, 1, args);
  }
  mrb_free(mrb, req);
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_data = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_write_cb write_cb = _uv_write_cb;
  uv_buf_t buf;
  uv_write_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_data);
  if (mrb_nil_p(b)) {
    write_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "write_cb"), b);

  buf = uv_buf_init((char*) RSTRING_PTR(arg_data), RSTRING_LEN(arg_data));
  req = (uv_write_t*) mrb_malloc(mrb, sizeof(uv_write_t));
  memset(req, 0, sizeof(uv_write_t));
  req->data = context;
  err = uv_write(req, (uv_stream_t*)&context->handle, &buf, 1, write_cb);
  if (err != 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_try_write(mrb_state *mrb, mrb_value self)
{
  uv_buf_t buf;
  mrb_value str;
  mrb_uv_handle *context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  int err;

  mrb_get_args(mrb, "S", &str);
  buf = uv_buf_init(RSTRING_PTR(str), RSTRING_LEN(str));
  err = uv_try_write((uv_stream_t*)&context->handle, &buf, 1);
  if (err < 0) {
    mrb_uv_check_error(mrb, err);
  } else if (err == 0) {
    return mrb_symbol_value(mrb_intern_lit(mrb, "need_queue"));
  } else {
    return mrb_fixnum_value(err);
  }
}

static void
_uv_shutdown_cb(uv_shutdown_t* req, int status)
{
  mrb_uv_handle* context = (mrb_uv_handle*) req->handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "shutdown_cb"));
  mrb_value args[1];
  args[0] = mrb_fixnum_value(status);
  mrb_yield_argv(mrb, proc, 1, args);
}

static mrb_value
mrb_uv_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_shutdown_cb shutdown_cb = _uv_shutdown_cb;
  uv_shutdown_t* req;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    shutdown_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "shutdown_cb"), b);

  req = (uv_shutdown_t*) mrb_malloc(mrb, sizeof(uv_shutdown_t));
  memset(req, 0, sizeof(uv_shutdown_t));
  req->data = context;
  uv_shutdown(req, (uv_stream_t*)&context->handle, shutdown_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_readable(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_bool_value(uv_is_readable((uv_stream_t*)&ctx->handle));
}

static mrb_value
mrb_uv_writable(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_bool_value(uv_is_writable((uv_stream_t*)&ctx->handle));
}

void
mrb_mruby_uv_gem_init_handle(mrb_state *mrb, struct RClass *UV)
{
  struct RClass* _class_uv_timer;
  struct RClass* _class_uv_idle;
  struct RClass* _class_uv_async;
  struct RClass* _class_uv_prepare;
  struct RClass* _class_uv_handle;
  struct RClass* _class_uv_tcp;
  struct RClass* _class_uv_udp;
  struct RClass* _class_uv_pipe;
  struct RClass* _class_uv_tty;
  struct RClass* _class_uv_process;
  struct RClass* _class_uv_fs_poll;
  struct RClass* _class_uv_signal;
  struct RClass* _class_uv_stream;
  int const ai = mrb_gc_arena_save(mrb);

  _class_uv_handle = mrb_define_module_under(mrb, UV, "Handle");
  mrb_define_method(mrb, _class_uv_handle, "close", mrb_uv_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "closing?", mrb_uv_is_closing, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "active?", mrb_uv_is_active, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "ref", mrb_uv_ref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "unref", mrb_uv_unref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "has_ref?", mrb_uv_has_ref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_handle, "data", mrb_uv_data_get, ARGS_NONE());

  _class_uv_stream = mrb_define_module_under(mrb, UV, "Stream");
  mrb_include_module(mrb, _class_uv_stream, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_stream, "write", mrb_uv_write, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_stream, "try_write", mrb_uv_try_write, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_stream, "shutdown", mrb_uv_shutdown, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "read_start", mrb_uv_read_start, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "read_stop", mrb_uv_read_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "readable?", mrb_uv_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "writable?", mrb_uv_writable, MRB_ARGS_NONE());

  _class_uv_tty = mrb_define_class_under(mrb, UV, "TTY", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_tty, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_tty, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_tty, "initialize", mrb_uv_tty_init, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tty, "set_mode", mrb_uv_tty_set_mode, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_tty, "reset_mode", mrb_uv_tty_reset_mode, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tty, "get_winsize", mrb_uv_tty_get_winsize, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_udp = mrb_define_class_under(mrb, UV, "UDP", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_udp, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_udp, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_udp, "initialize", mrb_uv_udp_init, ARGS_NONE());
  // TODO: uv_udp_open
  mrb_define_method(mrb, _class_uv_udp, "recv_start", mrb_uv_udp_recv_start, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "recv_stop", mrb_uv_udp_recv_stop, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send", mrb_uv_udp_send4, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "send6", mrb_uv_udp_send6, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "bind", mrb_uv_udp_bind4, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "bind6", mrb_uv_udp_bind6, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "getsockname", mrb_uv_udp_getsockname, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_process = mrb_define_class_under(mrb, UV, "Process", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_process, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_process, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_process, "initialize", mrb_uv_process_init, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "spawn", mrb_uv_process_spawn, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe=", mrb_uv_process_stdout_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe", mrb_uv_process_stdout_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe=", mrb_uv_process_stdin_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe", mrb_uv_process_stdin_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe=", mrb_uv_process_stderr_pipe_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe", mrb_uv_process_stderr_pipe_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "kill", mrb_uv_process_kill, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_signal = mrb_define_class_under(mrb, UV, "Signal", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_signal, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_signal, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_signal, "initialize", mrb_uv_signal_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_signal, "start", mrb_uv_signal_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_signal, "stop", mrb_uv_signal_stop, ARGS_NONE());
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

  _class_uv_fs_poll = mrb_define_class_under(mrb, mrb_class_get_under(mrb, UV, "FS"), "Poll", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_fs_poll, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_fs_poll, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_fs_poll, "initialize", mrb_uv_fs_poll_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_poll, "start", mrb_uv_fs_poll_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs_poll, "stop", mrb_uv_fs_poll_stop, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_timer = mrb_define_class_under(mrb, UV, "Timer", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_timer, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_timer, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_timer, "initialize", mrb_uv_timer_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "again", mrb_uv_timer_again, ARGS_NONE());
  // TODO: uv_timer_set_repeat
  // TODO: uv_timer_get_repeat
  mrb_define_method(mrb, _class_uv_timer, "start", mrb_uv_timer_start, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_timer, "stop", mrb_uv_timer_stop, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_idle = mrb_define_class_under(mrb, UV, "Idle", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_idle, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_idle, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_idle, "initialize", mrb_uv_idle_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "start", mrb_uv_idle_start, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "stop", mrb_uv_idle_stop, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_async = mrb_define_class_under(mrb, UV, "Async", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_async, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_async, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_async, "initialize", mrb_uv_async_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "send", mrb_uv_async_send, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_prepare = mrb_define_class_under(mrb, UV, "Prepare", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_prepare, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_prepare, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_prepare, "initialize", mrb_uv_prepare_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "start", mrb_uv_prepare_start, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "stop", mrb_uv_prepare_stop, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_tcp = mrb_define_class_under(mrb, UV, "TCP", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_tcp, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_tcp, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, ARGS_NONE());
  // TODO: uv_tcp_open
  // TODO: uv_udp_set_membership
  // TODO: uv_udp_set_multicast_loop
  // TODO: uv_udp_set_multicast_ttl
  // TODO: uv_udp_set_broadcast
  // TODO: uv_udp_set_ttl
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect4, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "connect6", mrb_uv_tcp_connect6, ARGS_REQ(2));
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
  mrb_define_method(mrb, _class_uv_tcp, "getpeername", mrb_uv_tcp_getpeername, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "getsockname", mrb_uv_tcp_getsockname, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_pipe = mrb_define_class_under(mrb, UV, "Pipe", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_pipe, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_pipe, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_pipe, "initialize", mrb_uv_pipe_init, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "open", mrb_uv_pipe_open, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "connect", mrb_uv_pipe_connect, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "bind", mrb_uv_pipe_bind, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "listen", mrb_uv_pipe_listen, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "accept", mrb_uv_pipe_accept, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_pipe, "pending_instances=", mrb_uv_pipe_pending_instances, ARGS_REQ(1));
  mrb_gc_arena_restore(mrb, ai);
}
