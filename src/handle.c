#include "mruby/uv.h"
#include "mrb_uv.h"

#include <mruby/variable.h>


mrb_value
mrb_uv_current_loop_obj(mrb_state *mrb) {
  return mrb_iv_get(
      mrb, mrb_const_get(
          mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "UV")),
      mrb_intern_lit(mrb, "current_loop"));
}

uv_loop_t*
mrb_uv_current_loop(mrb_state *mrb) {
  return (uv_loop_t*)mrb_uv_get_ptr(mrb, mrb_uv_current_loop_obj(mrb), &mrb_uv_loop_type);
}

static void
set_handle_cb(mrb_uv_handle *h, mrb_value b)
{
  mrb_state *mrb = h->mrb;
  if (mrb_nil_p(b)) {
    mrb_raise(mrb, mrb_class_get(mrb, "RuntimeError"), "block not passed");
  }
  if (!mrb_nil_p(h->block)) {
    mrb_raise(mrb, mrb_class_get(mrb, "RuntimeError"), "uv_handle_t callback already set.");
  }
  h->block = b;
  mrb_iv_set(mrb, h->instance, mrb_intern_lit(mrb, "uv_handle_cb"), b);
}

static void
yield_handle_cb(mrb_uv_handle *h, mrb_int argc, mrb_value const *argv)
{
  mrb_state *mrb = h->mrb;
  mrb_assert(!mrb_nil_p(h->block));
  mrb_yield_argv(mrb, h->block, argc, argv);
}

static uv_loop_t*
get_loop(mrb_state *mrb, mrb_value *v)
{
  if(mrb_nil_p(*v)) {
    *v = mrb_uv_current_loop_obj(mrb);
  }
  mrb_assert(!mrb_nil_p(*v));
  return (uv_loop_t*)mrb_uv_get_ptr(mrb, *v, &mrb_uv_loop_type);
}

static void
no_yield_close_cb(uv_handle_t *h)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)h->data;
  DATA_PTR(ctx->instance) = NULL;
  DATA_TYPE(ctx->instance) = NULL;
  mrb_free(ctx->mrb, ctx);
}

static void
mrb_uv_handle_free(mrb_state *mrb, void *p)
{
  mrb_uv_handle* context = (mrb_uv_handle*) p;
  if (!context) { return; }

  mrb_assert(mrb == context->mrb);
  mrb_assert(context->handle.type != UV_UNKNOWN_HANDLE);
  // mrb_assert(!uv_has_ref(&context->handle));

  if (!uv_is_closing(&context->handle)) {
    uv_close(&context->handle, no_yield_close_cb);
  }
}

void
mrb_uv_close_handle_belongs_to_vm(uv_handle_t *h, void *arg)
{
  mrb_state *mrb = (mrb_state*)arg;
  mrb_uv_handle* handle = (mrb_uv_handle*)h->data;

  if (!handle) { return; }
  if (handle->mrb != mrb) { return; }

  mrb_uv_handle_type.dfree(mrb, handle);
}

const struct mrb_data_type mrb_uv_handle_type = {
  "uv_handle", mrb_uv_handle_free
};

mrb_uv_handle*
mrb_uv_handle_alloc(mrb_state* mrb, uv_handle_type t, mrb_value instance, mrb_value loop)
{
  size_t const size = uv_handle_size(t);
  mrb_uv_handle* context = (mrb_uv_handle*) mrb_malloc(mrb, sizeof(mrb_uv_handle) + (size - sizeof(uv_handle_t)));
  context->mrb = mrb;
  context->instance = instance;
  context->block = mrb_nil_value();
  context->handle.data = context;
  context->handle.type = UV_UNKNOWN_HANDLE;
  mrb_assert(mrb_type(instance) == MRB_TT_DATA);
  DATA_PTR(instance) = context;
  DATA_TYPE(instance) = &mrb_uv_handle_type;
  mrb_assert(DATA_TYPE(loop) == &mrb_uv_loop_type);
  mrb_iv_set(mrb, instance, mrb_intern_lit(mrb, "loop"), loop);
  return context;
}

static void
_uv_done_cb(uv_req_t* uv_req, int status)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*) uv_req->data;
  mrb_value const arg = mrb_uv_create_status(req->mrb, status);
  mrb_uv_req_yield(req, 1, &arg);
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
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "close_cb"));
  mrb_assert(!mrb_nil_p(proc));
  mrb_yield_argv(mrb, proc, 0, NULL);
  mrb_iv_remove(mrb, context->instance, mrb_intern_lit(mrb, "close_cb"));
  DATA_PTR(context->instance) = NULL;
  mrb_free(mrb, context);
}

static mrb_value
mrb_uv_close(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();

  mrb_get_args(mrb, "&", &b);
  DATA_PTR(self) = NULL;
  if (mrb_nil_p(b)) {
    uv_close(&context->handle, no_yield_close_cb);
  } else {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "close_cb"), b);
    mrb_uv_gc_protect(mrb, self);
    uv_close(&context->handle, _uv_close_cb);
  }
  return self;
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

static mrb_value
mrb_uv_recv_buffer_size(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  int v = 0;
  mrb_uv_check_error(mrb, uv_recv_buffer_size(&ctx->handle, &v));
  return mrb_fixnum_value(v);
}

static mrb_value
mrb_uv_recv_buffer_size_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_int tmp_v;
  int v;
  mrb_get_args(mrb, "i", &tmp_v);
  v = tmp_v;
  mrb_uv_check_error(mrb, uv_recv_buffer_size(&ctx->handle, &v));
  return self;
}

static mrb_value
mrb_uv_send_buffer_size(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  int v = 0;
  mrb_uv_check_error(mrb, uv_send_buffer_size(&ctx->handle, &v));
  return mrb_fixnum_value(v);
}

static mrb_value
mrb_uv_send_buffer_size_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_int tmp_v;
  int v;
  mrb_get_args(mrb, "i", &tmp_v);
  v = tmp_v;
  mrb_uv_check_error(mrb, uv_send_buffer_size(&ctx->handle, &v));
  return self;
}

static mrb_value
mrb_uv_fileno(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  uv_os_fd_t fd;
  mrb_uv_check_error(mrb, uv_fileno(&ctx->handle, &fd));
  return mrb_uv_from_uint64(mrb, fd);
}

#if !MRB_UV_CHECK_VERSION(1, 19, 0)
#define uv_handle_get_loop(h) ((h)->loop)
#endif

static mrb_value
mrb_uv_handle_loop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value ret = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "loop"));

  mrb_assert(uv_handle_get_loop(&ctx->handle) == ((uv_loop_t*)mrb_uv_get_ptr(mrb, ret, &mrb_uv_loop_type)));

  return ret;
}

#if MRB_UV_CHECK_VERSION(1, 19, 0)

static mrb_value
mrb_uv_handle_get_type(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_handle_get_type(&ctx->handle));
}

#endif

static mrb_value
mrb_uv_handle_type_name(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
#if MRB_UV_CHECK_VERSION(1, 19, 0)
  return mrb_symbol_value(mrb_intern_cstr(mrb, uv_handle_type_name(uv_handle_get_type(&ctx->handle))));
#else
  uv_handle_type const t = ctx->handle.type;
  switch(t) {
#define XX(u, l) case UV_ ## u: return symbol_value_lit(mrb, #l);
      UV_HANDLE_TYPE_MAP(XX)
#undef XX

  default:
    mrb_raisef(mrb, E_TYPE_ERROR, "Invalid uv_handle_t type: %S", mrb_fixnum_value(t));
    return self;
  }
#endif
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

  mrb_get_args(mrb, "|oo", &arg_ipc, &arg_loop);
  loop = get_loop(mrb, &arg_loop);
  if (!mrb_nil_p(arg_ipc)) {
    if (mrb_fixnum_p(arg_ipc))
      ipc = mrb_fixnum(arg_ipc);
    else
      ipc = mrb_bool(arg_ipc);
  }

  context = mrb_uv_handle_alloc(mrb, UV_NAMED_PIPE, self, arg_loop);

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
  return self;
}

static mrb_value
mrb_uv_pipe_connect(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value(), ret;
  char* name;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&z", &b, &name);
  req = mrb_uv_req_current(mrb, b, &ret);
  uv_pipe_connect(&req->req.connect, (uv_pipe_t*)&context->handle, name, (uv_connect_cb)_uv_done_cb);
  return ret;
}

static mrb_value
mrb_uv_pipe_bind(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  const char* name;

  mrb_get_args(mrb, "z", &name);
  mrb_uv_check_error(mrb, uv_pipe_bind((uv_pipe_t*)&context->handle, name));
  return self;
}

static mrb_value
mrb_uv_pipe_pending_instances(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_count = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_count);
  uv_pipe_pending_instances((uv_pipe_t*)&context->handle, arg_count);
  return self;
}

static mrb_value
mrb_uv_pipe_getsockname(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  mrb_get_args(mrb, "");

  mrb_str_resize(mrb, buf, BUF_SIZE);
  res = uv_pipe_getsockname((uv_pipe_t*)&context->handle, RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_pipe_getsockname((uv_pipe_t*)&context->handle, RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

#if MRB_UV_CHECK_VERSION(1, 3, 0)

static mrb_value
mrb_uv_pipe_getpeername(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  mrb_get_args(mrb, "");

  mrb_str_resize(mrb, buf, BUF_SIZE);
  res = uv_pipe_getpeername((uv_pipe_t*)&context->handle, RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_pipe_getpeername((uv_pipe_t*)&context->handle, RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 16, 0)

static mrb_value
mrb_uv_pipe_chmod(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_int mode;
  mrb_get_args(mrb, "i", &mode);

  mrb_uv_check_error(mrb, uv_pipe_chmod((uv_pipe_t*)&context->handle, mode));
  return self;
}

#endif

/*********************************************************
 * UV::TCP
 *********************************************************/
static mrb_value
mrb_uv_tcp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;
  mrb_int flags;

  mrb_int c = mrb_get_args(mrb, "|oi", &arg_loop, &flags);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_TCP, self, arg_loop);

  if (c == 2 && MRB_UV_CHECK_VERSION(1, 7, 0)) {
#if MRB_UV_CHECK_VERSION(1, 7, 0)
    mrb_uv_check_error(mrb, uv_tcp_init_ex(loop, (uv_tcp_t*)&context->handle, flags));
#endif
  } else {
    mrb_uv_check_error(mrb, uv_tcp_init(loop, (uv_tcp_t*)&context->handle));
  }
  return self;
}

static mrb_value
mrb_uv_tcp_open(mrb_state *mrb, mrb_value self)
{
  mrb_value socket;
  mrb_uv_handle *ctx;
  mrb_get_args(mrb, "o", &socket);
  ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_tcp_open((uv_tcp_t*)&ctx->handle, mrb_uv_to_socket(mrb, socket)));
  return self;
}

static mrb_value
mrb_uv_tcp_connect(mrb_state *mrb, mrb_value self, int version)
{
  mrb_value arg_addr;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value(), ret;
  struct sockaddr_storage* addr = NULL;
  mrb_uv_req_t* req;

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

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_tcp_connect(
      &req->req.connect, (uv_tcp_t*)&context->handle, ((const struct sockaddr *) addr), (uv_connect_cb)_uv_done_cb));
  return ret;
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
  return self;
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
mrb_uv_tcp_simultaneous_accepts_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "simultaneous_accepts"));
}

static mrb_value
mrb_uv_tcp_simultaneous_accepts_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_simultaneous_accepts;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_simultaneous_accepts);
  uv_tcp_simultaneous_accepts((uv_tcp_t*)&context->handle, arg_simultaneous_accepts);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "simultaneous_accepts"), mrb_bool_value(arg_simultaneous_accepts));
  return self;
}

static mrb_value
mrb_uv_tcp_keepalive_delay(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "keepalive"));
}

static mrb_value
mrb_uv_tcp_keepalive_p(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb_iv_defined(mrb, self, mrb_intern_lit(mrb, "keepalive")));
}

static mrb_value
mrb_uv_tcp_keepalive_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_keepalive, arg_delay;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "ii", &arg_keepalive, &arg_delay);
  uv_tcp_keepalive((uv_tcp_t*)&context->handle, arg_keepalive, arg_delay);
  if (arg_keepalive) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "keepalive"), mrb_fixnum_value(arg_delay));
  } else {
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "keepalive"));
  }
  return self;
}

static mrb_value
mrb_uv_tcp_nodelay_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "nodelay"));
}

static mrb_value
mrb_uv_tcp_nodelay_set(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_nodelay;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_nodelay);
  uv_tcp_nodelay((uv_tcp_t*)&context->handle, arg_nodelay);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "nodelay"), mrb_bool_value(arg_nodelay));
  return self;
}

static mrb_value
sockaddr_to_mrb(mrb_state *mrb, struct sockaddr *addr)
{
  struct RClass *class_uv, *class_uv_ipaddr;
  struct RData *data;
  mrb_value value_data, value_result;
  switch (addr->sa_family) {
    case AF_INET:
    case AF_INET6:
      class_uv = mrb_module_get(mrb, "UV");
      if (addr->sa_family == AF_INET) {
        class_uv_ipaddr = mrb_class_get_under(mrb, class_uv, "Ip4Addr");
        data = Data_Wrap_Struct(
            mrb, mrb->object_class,
            &mrb_uv_ip4addr_nofree_type, (void *) &addr);
      }
      else {
        class_uv_ipaddr = mrb_class_get_under(mrb, class_uv, "Ip6Addr");
        data = Data_Wrap_Struct(
            mrb, mrb->object_class,
            &mrb_uv_ip6addr_nofree_type, (void *) &addr);
      }
      value_data = mrb_obj_value((void *) data);
      value_result = mrb_class_new_instance(mrb, 1, &value_data, class_uv_ipaddr);
      break;
    default:
      mrb_assert(FALSE);
  }
  return value_result;
}

static mrb_value
mrb_uv_tcp_getpeername(mrb_state *mrb, mrb_value self)
{
  int len;
  struct sockaddr_storage addr;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  len = sizeof(addr);
  mrb_uv_check_error(mrb, uv_tcp_getpeername((uv_tcp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  return sockaddr_to_mrb(mrb, (struct sockaddr *)&addr);
}

static mrb_value
mrb_uv_getsockname(mrb_state *mrb, mrb_value self, int tcp)
{
  int len;
  struct sockaddr_storage addr;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  len = sizeof(addr);
  if (tcp) {
    mrb_uv_check_error(mrb, uv_tcp_getsockname((uv_tcp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  }
  else {
    mrb_uv_check_error(mrb, uv_udp_getsockname((uv_udp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  }
  return sockaddr_to_mrb(mrb, (struct sockaddr*)&addr);
}

static mrb_value
mrb_uv_tcp_getsockname(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_getsockname(mrb, self, 1);
}

#if MRB_UV_CHECK_VERSION(1, 32, 0)

static mrb_value
mrb_uv_tcp_close_reset(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();

  mrb_get_args(mrb, "&", &b);

  mrb_iv_set(mrb, context->instance, mrb_intern_lit(mrb, "close_cb"), b);
  mrb_uv_check_error(mrb, uv_tcp_close_reset(
      (uv_tcp_t*)&context->handle, (uv_close_cb)_uv_close_cb));
  return mrb_nil_value();
}

#endif

/*********************************************************
 * UV::UDP
 *********************************************************/
static mrb_value
mrb_uv_udp_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;
  mrb_int flags;

  mrb_int c = mrb_get_args(mrb, "|oi", &arg_loop, &flags);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_UDP, self, arg_loop);

  if (c == 2 && MRB_UV_CHECK_VERSION(1, 7, 0)) {
#if MRB_UV_CHECK_VERSION(1, 7, 0)
    mrb_uv_check_error(mrb, uv_udp_init_ex(loop, (uv_udp_t*)&context->handle, flags));
#endif
  } else {
    mrb_uv_check_error(mrb, uv_udp_init(loop, (uv_udp_t*)&context->handle));
  }
  return self;
}

static mrb_value
mrb_uv_udp_open(mrb_state *mrb, mrb_value self)
{
  mrb_value socket;
  mrb_uv_handle *ctx;
  mrb_get_args(mrb, "o", &socket);
  ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_udp_open((uv_udp_t*)&ctx->handle, mrb_uv_to_socket(mrb, socket)));
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
  return self;
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
_uv_udp_send_cb(uv_udp_send_t* uv_req, int status)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*) uv_req->data;
  mrb_value const arg = mrb_uv_create_status(req->mrb, status);
  mrb_uv_req_yield(req, 1, &arg);
}

static mrb_value
mrb_uv_udp_send(mrb_state *mrb, mrb_value self, int version)
{
  mrb_value arg_data = mrb_nil_value(), arg_addr = mrb_nil_value();
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  struct sockaddr_storage* addr = NULL;
  mrb_value b = mrb_nil_value(), ret;
  uv_buf_t buf;
  mrb_uv_req_t* req;

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

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_set_buf(req, &buf, arg_data);
  mrb_uv_req_check_error(mrb, req, uv_udp_send(
      &req->req.udp_send, (uv_udp_t*)&context->handle, &buf, 1,
      ((const struct sockaddr *) addr), _uv_udp_send_cb));
  return ret;
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
  mrb_value args[3];
  struct RClass* _class_uv;
  struct RClass* _class_uv_ipaddr = NULL;
  struct RData* data = NULL;
  mrb_value value_data, value_addr = mrb_nil_value();

  mrb_uv_check_error(mrb, nread);

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
  args[2] = mrb_fixnum_value(flags);
  mrb_free(mrb, buf->base);
  yield_handle_cb(context, 3, args);
}

static mrb_value
mrb_uv_udp_recv_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_udp_recv_cb udp_recv_cb = _uv_udp_recv_cb;

  mrb_get_args(mrb, "&", &b);
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_udp_recv_start((uv_udp_t*)&context->handle, _uv_alloc_cb, udp_recv_cb));
  return self;
}

static mrb_value
mrb_uv_udp_recv_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_udp_recv_stop((uv_udp_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_udp_getsockname(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_getsockname(mrb, self, 0);
}

static mrb_value
mrb_uv_udp_set_membership(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  char *multicast, *iface;
  mrb_int mem;

  mrb_get_args(mrb, "zzi", &multicast, &iface, &mem);
  mrb_uv_check_error(mrb, uv_udp_set_membership((uv_udp_t*)&ctx->handle, multicast, iface, mem));
  return self;
}

static mrb_value
mrb_uv_udp_multicast_loop_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_bool b;

  mrb_get_args(mrb, "b", &b);
  mrb_uv_check_error(mrb, uv_udp_set_multicast_loop((uv_udp_t*)&ctx->handle, b));
  return mrb_bool_value(b);
}

static mrb_value
mrb_uv_udp_multicast_ttl_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_bool b;

  mrb_get_args(mrb, "b", &b);
  mrb_uv_check_error(mrb, uv_udp_set_multicast_ttl((uv_udp_t*)&ctx->handle, b));
  return mrb_bool_value(b);
}

static mrb_value
mrb_uv_udp_broadcast_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_bool b;

  mrb_get_args(mrb, "b", &b);
  mrb_uv_check_error(mrb, uv_udp_set_broadcast((uv_udp_t*)&ctx->handle, b));
  return mrb_bool_value(b);
}

static mrb_value
mrb_uv_udp_multicast_interface_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value s;

  mrb_get_args(mrb, "S", &s);
  mrb_uv_check_error(mrb, uv_udp_set_multicast_interface((uv_udp_t*)&ctx->handle, mrb_string_value_ptr(mrb, s)));
  return s;
}

static mrb_value
mrb_uv_udp_ttl_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_int v;

  mrb_get_args(mrb, "i", &v);
  mrb_uv_check_error(mrb, uv_udp_set_ttl((uv_udp_t*)&ctx->handle, v));
  return mrb_fixnum_value(v);
}

static mrb_value
mrb_uv_udp_try_send(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value s, a;
  int err;
  uv_buf_t buf;
  const struct sockaddr* addr;

  mrb_get_args(mrb, "So", &s, &a);
  mrb_str_modify(mrb, mrb_str_ptr(s));
  buf = uv_buf_init(RSTRING_PTR(s), RSTRING_LEN(s));
  addr = mrb_data_check_get_ptr(mrb, a, &mrb_uv_ip4addr_type);
  if (!addr) {
    mrb_data_get_ptr(mrb, a, &mrb_uv_ip6addr_type);
  }

  err = uv_udp_try_send((uv_udp_t*)&ctx->handle, &buf, 1, addr);
  mrb_uv_check_error(mrb, err);

  return mrb_fixnum_value(err);
}

#if !MRB_UV_CHECK_VERSION(1, 19, 0)
#define uv_udp_get_send_queue_size(u) ((u)->send_queue_size)
#define uv_udp_get_send_queue_count(u) ((u)->send_queue_count)
#endif

static mrb_value
mrb_uv_udp_send_queue_count(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_udp_get_send_queue_count((uv_udp_t*)&ctx->handle));
}

static mrb_value
mrb_uv_udp_send_queue_size(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_udp_get_send_queue_size((uv_udp_t*)&ctx->handle));
}

#if MRB_UV_CHECK_VERSION(1, 27, 0)

static mrb_value
mrb_uv_udp_get_peername(mrb_state *mrb, mrb_value self)
{
  int len;
  struct sockaddr_storage addr;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  len = sizeof(addr);
  mrb_uv_check_error(mrb, uv_udp_getpeername((uv_udp_t*)&context->handle, (struct sockaddr *)&addr, &len));
  return sockaddr_to_mrb(mrb, (struct sockaddr *)&addr);
}

static mrb_value
mrb_uv_udp_connect(mrb_state *mrb, mrb_value self)
{
  struct sockaddr* addr;
  mrb_value addr_obj;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "o", &addr_obj);
  if (mrb_type(addr_obj) != MRB_TT_DATA) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "Invalid sockaddr: %S", addr_obj);
  }
  addr =
      DATA_PTR(addr_obj) == &mrb_uv_ip4addr_type? (struct sockaddr*)DATA_PTR(addr_obj):
      DATA_PTR(addr_obj) == &mrb_uv_ip4addr_nofree_type? (struct sockaddr*)DATA_PTR(addr_obj):
      DATA_PTR(addr_obj) == &mrb_uv_ip6addr_type? (struct sockaddr*)DATA_PTR(addr_obj):
      DATA_PTR(addr_obj) == &mrb_uv_ip6addr_nofree_type? (struct sockaddr*)DATA_PTR(addr_obj):
      NULL;
  if (!addr) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "Invalid sockaddr: %S", addr_obj);
  }

  mrb_uv_check_error(mrb, uv_udp_connect((uv_udp_t*)&context->handle, addr));
  return self;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 32, 0)

static mrb_value
mrb_uv_udp_set_source_membership(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  const char *mc, *inf, *src;
  mrb_int mem;

  mrb_get_args(mrb, "zzzi", &mc, &inf, &src, &mem);

  mrb_uv_check_error(mrb, uv_udp_set_source_membership((uv_udp_t*)&context->handle, mc, inf, src, mem));
  return self;
}

#endif

/*********************************************************
 * UV::Prepare
 *********************************************************/
static void
_uv_prepare_cb(uv_prepare_t* prepare)
{
  yield_handle_cb((mrb_uv_handle*) prepare->data, 0, NULL);
}

static mrb_value
mrb_uv_prepare_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_PREPARE, self, arg_loop);

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
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_prepare_start((uv_prepare_t*)&context->handle, prepare_cb));
  return self;
}

static mrb_value
mrb_uv_prepare_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_prepare_stop((uv_prepare_t*)&context->handle));
  return self;
}

/*********************************************************
 * UV::Async
 *********************************************************/
static void
_uv_async_cb(uv_async_t* async)
{
  yield_handle_cb((mrb_uv_handle*) async->data, 0, NULL);
}

static mrb_value
mrb_uv_async_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;
  mrb_value b;

  mrb_get_args(mrb, "&|o", &b, &arg_loop);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_ASYNC, self, arg_loop);

  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_async_init(loop, (uv_async_t*)&context->handle, _uv_async_cb));
  return self;
}

static mrb_value
mrb_uv_async_send(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_check_error(mrb, uv_async_send((uv_async_t*)&context->handle));
  return self;
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
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_IDLE, self, arg_loop);

  mrb_uv_check_error(mrb, uv_idle_init(loop, (uv_idle_t*)&context->handle));
  return self;
}

static void
_uv_idle_cb(uv_idle_t* idle)
{
  yield_handle_cb((mrb_uv_handle*)idle->data, 0, NULL);
}

static mrb_value
mrb_uv_idle_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();

  mrb_get_args(mrb, "&", &b);
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_idle_start((uv_idle_t*)&context->handle, mrb_nil_p(b)? NULL : _uv_idle_cb));
  return self;
}

static mrb_value
mrb_uv_idle_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_idle_stop((uv_idle_t*)&context->handle));
  return self;
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
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_TTY, self, arg_loop);

  mrb_uv_check_error(mrb, uv_tty_init(loop, (uv_tty_t*)&context->handle, arg_file, arg_readable));
  return self;
}

static mrb_value
mrb_uv_tty_set_mode(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_mode = -1;
  mrb_value mode_val;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "o", &mode_val);

  if (mrb_fixnum_p(mode_val)) {
    arg_mode = mrb_fixnum(mode_val);
#if MRB_UV_CHECK_VERSION(1, 2, 0)
  } else if (mrb_symbol_p(mode_val)) {
    mrb_sym s = mrb_symbol(mode_val);
    if (s == mrb_intern_lit(mrb, "raw")) { arg_mode = UV_TTY_MODE_RAW; }
    else if (s == mrb_intern_lit(mrb, "normal")) { arg_mode = UV_TTY_MODE_NORMAL; }
    else if (s == mrb_intern_lit(mrb, "io")) { arg_mode = UV_TTY_MODE_IO; }
#endif
  }

  if (arg_mode == -1) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "invalid tty mode: %S", mode_val);
  }

  return mrb_fixnum_value(uv_tty_set_mode((uv_tty_t*)&context->handle, arg_mode));
}

static mrb_value
mrb_uv_tty_reset_mode(mrb_state *mrb, mrb_value self)
{
  uv_tty_reset_mode();
  return self;
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
  mrb_value args[2];
  args[0] = mrb_fixnum_value(exit_status);
  args[1] = mrb_fixnum_value(term_signal);
  yield_handle_cb((mrb_uv_handle*)process->data, 2, args);
}

mrb_value
mrb_uv_get_hash_opt(mrb_state *mrb, mrb_value h, const char *str)
{
  mrb_value ret = mrb_hash_get(mrb, h, mrb_symbol_value(mrb_intern_cstr(mrb, str)));
  if (mrb_nil_p(ret)) {
    ret = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, str));
  }
  return ret;
}

static mrb_value
mrb_uv_process_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_opt = mrb_nil_value();

  mrb_get_args(mrb, "H", &arg_opt);

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
  mrb_value b;
  mrb_value options;
  mrb_value
      arg_file, arg_args, arg_env, arg_cwd, arg_uid, arg_gid, arg_detached,
      arg_windows_hide, arg_windows_verbatim_arguments, arg_stdio;
#if MRB_UV_CHECK_VERSION(1, 24, 0)
  mrb_value arg_windows_hide_console, arg_windows_hide_gui;
#endif
  mrb_value stdio_pipe[3];
  char cwd[PATH_MAX];
  size_t cwd_size = sizeof(cwd);
  int i, err;
  uv_stdio_container_t stdio[3];
  uv_process_options_t opt = {0};
  const char** args;
  mrb_value arg_loop = mrb_nil_value();
  uv_loop_t *loop;

  options = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "options"));
  arg_file = mrb_uv_get_hash_opt(mrb, options, "file");
  arg_args = mrb_uv_get_hash_opt(mrb, options, "args");
  arg_env = mrb_uv_get_hash_opt(mrb, options, "env");
  arg_cwd = mrb_uv_get_hash_opt(mrb, options, "cwd");
  arg_uid = mrb_uv_get_hash_opt(mrb, options, "uid");
  arg_gid = mrb_uv_get_hash_opt(mrb, options, "gid");
  arg_detached = mrb_uv_get_hash_opt(mrb, options, "detached");
  arg_windows_verbatim_arguments = mrb_uv_get_hash_opt(mrb, options, "windows_verbatim_arguments");
  arg_windows_hide = mrb_uv_get_hash_opt(mrb, options, "windows_hide");
#if MRB_UV_CHECK_VERSION(1, 24, 0)
  arg_windows_hide_console = mrb_uv_get_hash_opt(mrb, options, "windows_hide_console");
  arg_windows_hide_gui = mrb_uv_get_hash_opt(mrb, options, "windows_hide_gui");
#endif
  arg_stdio = mrb_uv_get_hash_opt(mrb, options, "stdio");
  stdio_pipe[0] = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdin_pipe"));
  stdio_pipe[1] = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stdout_pipe"));
  stdio_pipe[2] = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "stderr_pipe"));

  mrb_get_args(mrb, "|o&", &arg_loop, &b);

  // stdio settings
  opt.stdio_count = 3;
  opt.stdio = stdio;
  if (mrb_bool(arg_stdio)) {
    int len;
    mrb_check_type(mrb, arg_stdio, MRB_TT_ARRAY);
    len = RARRAY_LEN(arg_stdio);
    if (len > 3) { len = 3; }
    for (i = 0; i < len; i++) {
      stdio_pipe[i] = RARRAY_PTR(arg_stdio)[i];
    }
    for (; i < 3; ++i) {
      stdio_pipe[i] = mrb_nil_value();
    }
  }
  for (i = 0; i < 3; ++i) {
    mrb_value obj = stdio_pipe[i];
    if (mrb_bool(obj)) {
      if (mrb_fixnum_p(obj)) {
        stdio[i].flags = UV_INHERIT_FD;
        stdio[i].data.fd = mrb_fixnum(obj);
      } else {
        mrb_uv_handle* pcontext = (mrb_uv_handle*)mrb_data_get_ptr(mrb, obj, &mrb_uv_handle_type);
        if (uv_is_active(&pcontext->handle)) {
          stdio[i].flags = UV_INHERIT_STREAM;
          stdio[i].data.stream = (uv_stream_t*)&pcontext->handle;
        } else {
          stdio[i].flags = UV_CREATE_PIPE;
          if (i == 0) { stdio[i].flags |= UV_READABLE_PIPE; }
          else { stdio[i].flags |= UV_WRITABLE_PIPE; }
          stdio[i].data.stream = (uv_stream_t*)&pcontext->handle;
        }
      }
    } else {
      stdio[i].flags = UV_IGNORE;
    }
  }

  // command path
  opt.file = mrb_string_value_ptr(mrb, arg_file);

  // command line arguments
  mrb_check_type(mrb, arg_args, MRB_TT_ARRAY);
  args = mrb_malloc(mrb, sizeof(char*) * (RARRAY_LEN(arg_args)+2));
  args[0] = opt.file;
  for (i = 0; i < RARRAY_LEN(arg_args); i++) {
    args[i+1] = mrb_string_value_ptr(mrb, mrb_ary_entry(arg_args, i));
  }
  args[i+1] = NULL;
  opt.args = (char**) args;

  // environment variables
  if (mrb_bool(arg_env)) {
    if (mrb_hash_p(arg_env)) {
      mrb_value keys = mrb_hash_keys(mrb, arg_env);
      opt.env = mrb_malloc(mrb, sizeof(char*) * (RARRAY_LEN(keys) + 1));
      for (i = 0; i < RARRAY_LEN(keys); ++i) {
        mrb_value str = mrb_str_dup(mrb, mrb_str_to_str(mrb, RARRAY_PTR(keys)[i]));
        str = mrb_str_cat_lit(mrb, str, "=");
        mrb_str_concat(mrb, str, mrb_hash_get(mrb, arg_env, RARRAY_PTR(keys)[i]));
        opt.env[i] = mrb_str_to_cstr(mrb, str);
      }
    } else {
      mrb_check_type(mrb, arg_env, MRB_TT_ARRAY);
      opt.env = mrb_malloc(mrb, sizeof(char*) * (RARRAY_LEN(arg_env) + 1));
      for (i = 0; i < RARRAY_LEN(arg_env); i++) {
        opt.env[i] = mrb_str_to_cstr(mrb, RARRAY_PTR(arg_env)[i]);
      }
    }
    opt.env[i] = NULL;
  } else {
    opt.env = NULL; /* inherit parent */
  }

  // current directory
  if (mrb_bool(arg_cwd)) {
    opt.cwd = mrb_str_to_cstr(mrb, arg_cwd);
  } else {
    uv_cwd(cwd, &cwd_size);
    opt.cwd = cwd;
  }

  // set flags
  opt.flags = 0;
  if (mrb_bool(arg_uid)) {
    opt.uid = mrb_int(mrb, arg_uid);
    opt.flags |= UV_PROCESS_SETUID;
  }
  if (mrb_bool(arg_gid)) {
    opt.gid = mrb_int(mrb, arg_gid);
    opt.flags |= UV_PROCESS_SETGID;
  }
  if (mrb_bool(arg_detached)) { opt.flags |= UV_PROCESS_DETACHED; }
  if (mrb_bool(arg_windows_hide)) { opt.flags |= UV_PROCESS_WINDOWS_HIDE; }
#if MRB_UV_CHECK_VERSION(1, 24, 0)
  if (mrb_bool(arg_windows_hide_console)) { opt.flags |= UV_PROCESS_WINDOWS_HIDE_CONSOLE; }
  if (mrb_bool(arg_windows_hide_gui)) { opt.flags |= UV_PROCESS_WINDOWS_HIDE_GUI; }
#endif
  if (mrb_bool(arg_windows_verbatim_arguments)) { opt.flags |= UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS; }

  opt.exit_cb = _uv_exit_cb;

  loop = get_loop(mrb, &arg_loop);
  context = mrb_uv_handle_alloc(mrb, UV_PROCESS, self, arg_loop);
  set_handle_cb(context, b);
  err = uv_spawn(loop, (uv_process_t*)&context->handle, &opt);
  mrb_free(mrb, args);
  mrb_free(mrb, opt.env);
  mrb_uv_check_error(mrb, err);
  return self;
}

static mrb_value
mrb_uv_process_kill(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "i", &arg_signum);

  return mrb_fixnum_value(uv_process_kill((uv_process_t*)&context->handle, arg_signum));
}

#if !MRB_UV_CHECK_VERSION(1, 19, 0)
#define uv_process_get_pid(p) ((p)->pid)
#endif

static mrb_value
mrb_uv_process_pid(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_process_get_pid((uv_process_t*)&context->handle));
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
  return self;
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
  return self;
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
  return self;
}

#if MRB_UV_CHECK_VERSION(1, 23, 0)

static mrb_value
mrb_uv_process_get_priority(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  uv_pid_t pid = uv_process_get_pid((uv_process_t*)&context->handle);
  int priority;
  mrb_uv_check_error(mrb, uv_os_getpriority(pid, &priority));
  return mrb_fixnum_value(priority);
}

static mrb_value
mrb_uv_process_set_priority(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  uv_pid_t pid = uv_process_get_pid((uv_process_t*)&context->handle);
  int priority;

  mrb_get_args(mrb, "i", &priority);

  mrb_uv_check_error(mrb, uv_os_setpriority(pid, priority));
  return mrb_fixnum_value(priority);
}

#endif

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
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_TIMER, self, arg_loop);

  mrb_uv_check_error(mrb, uv_timer_init(loop, (uv_timer_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_timer_again(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_timer_again((uv_timer_t*)&context->handle));
  return self;
}

static void
_uv_timer_cb(uv_timer_t* timer)
{
  yield_handle_cb((mrb_uv_handle*)timer->data, 0, NULL);
}

static mrb_value
mrb_uv_timer_start(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_timeout = 0, arg_repeat = 0;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b;

  mrb_get_args(mrb, "&ii", &b, &arg_timeout, &arg_repeat);
  context->block = mrb_nil_value();
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_timer_start((uv_timer_t*)&context->handle, _uv_timer_cb,
                                         arg_timeout, arg_repeat));
  return self;
}

static mrb_value
mrb_uv_timer_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_timer_stop((uv_timer_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_timer_repeat(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_uv_from_uint64(mrb, uv_timer_get_repeat((uv_timer_t*)&ctx->handle));
}

static mrb_value
mrb_uv_timer_repeat_set(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_float f;
  mrb_get_args(mrb, "f", &f);
  return uv_timer_set_repeat((uv_timer_t*)&ctx->handle, (uint64_t)f), mrb_float_value(mrb, f);
}

/*********************************************************
 * UV::FS::Poll
 *********************************************************/
static void
_uv_fs_poll_cb(uv_fs_poll_t* handle, int status, const uv_stat_t* prev, const uv_stat_t* curr)
{
  mrb_uv_handle* context = (mrb_uv_handle*) handle->data;
  mrb_state* mrb = context->mrb;
  mrb_value args[3];
  args[0] = mrb_uv_create_status(mrb, status);
  args[1] = mrb_uv_create_stat(mrb, prev);
  args[2] = mrb_uv_create_stat(mrb, curr);
  yield_handle_cb(context, 3, args);
}

static mrb_value
mrb_uv_fs_poll_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_FS_POLL, self, arg_loop);

  mrb_uv_check_error(mrb, uv_fs_poll_init(loop, (uv_fs_poll_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_fs_poll_start(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_value b;
  mrb_int arg_interval;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_get_args(mrb, "&zi", &b, &arg_path, &arg_interval);
  set_handle_cb(context, b);
  return mrb_fixnum_value(uv_fs_poll_start(
      (uv_fs_poll_t*)&context->handle, _uv_fs_poll_cb, arg_path, arg_interval));
}

static mrb_value
mrb_uv_fs_poll_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_fs_poll_stop((uv_fs_poll_t*)&context->handle));
}

static mrb_value
mrb_uv_fs_poll_getpath(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  enum { BUF_SIZE = 128 };
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  char const *env;
  mrb_get_args(mrb, "z", &env);

  mrb_str_resize(mrb, buf, BUF_SIZE);

  res = uv_fs_poll_getpath((uv_fs_poll_t*)&context->handle, RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_fs_poll_getpath((uv_fs_poll_t*)&context->handle, RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

/*********************************************************
 * UV::Check
 *********************************************************/
static mrb_value
mrb_uv_check_init(mrb_state *mrb, mrb_value self)
{
  mrb_value l = mrb_nil_value();
  mrb_uv_handle *context;
  uv_loop_t *loop;
  mrb_get_args(mrb, "|o", &l);

  loop = get_loop(mrb, &l);
  context = mrb_uv_handle_alloc(mrb, UV_CHECK, self, l);
  mrb_uv_check_error(mrb, uv_check_init(loop, (uv_check_t*)&context->handle));
  return self;
}

static void
_uv_check_cb(uv_check_t *check)
{
  yield_handle_cb((mrb_uv_handle*)check->data, 0, NULL);
}

static mrb_value
mrb_uv_check_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b;
  mrb_get_args(mrb, "&", &b);
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_check_start((uv_check_t*)&context->handle, _uv_check_cb));
  return self;
}

static mrb_value
mrb_uv_check_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_check_error(mrb, uv_check_stop((uv_check_t*)&context->handle));
  return self;
}

/*********************************************************
 * UV::Signal
 *********************************************************/
static void
_uv_signal_cb(uv_signal_t* handle, int signum)
{
  mrb_value const arg = mrb_fixnum_value(signum);
  yield_handle_cb((mrb_uv_handle*) handle->data, 1, &arg);
}

static mrb_value
mrb_uv_signal_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_loop = mrb_nil_value();
  mrb_uv_handle* context = NULL;
  uv_loop_t* loop;

  mrb_get_args(mrb, "|o", &arg_loop);
  loop = get_loop(mrb, &arg_loop);

  context = mrb_uv_handle_alloc(mrb, UV_SIGNAL, self, arg_loop);

  mrb_uv_check_error(mrb, uv_signal_init(loop, (uv_signal_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_signal_start(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_signum;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b;

  mrb_get_args(mrb, "&i", &b, &arg_signum);
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_signal_start((uv_signal_t*)&context->handle, _uv_signal_cb, arg_signum));
  return self;
}

#if MRB_UV_CHECK_VERSION(1, 12, 0)

static mrb_value
mrb_uv_signal_start_oneshot(mrb_state *mrb, mrb_value self)
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

  return mrb_fixnum_value(uv_signal_start_oneshot((uv_signal_t*)&context->handle, signal_cb, arg_signum));
}

#endif

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
  mrb_value arg;

  mrb_gc_protect(mrb, context->block);

  if (nread < 0) {
    arg = mrb_uv_create_error(mrb, nread);
  } else {
    arg = mrb_str_new(mrb, buf->base, nread);
  }
  mrb_free(mrb, buf->base);
  yield_handle_cb(context, 1, &arg);
}

static mrb_value
mrb_uv_read_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b;

  mrb_get_args(mrb, "&", &b);
  set_handle_cb(context, b);
  mrb_uv_check_error(mrb, uv_read_start((uv_stream_t*)&context->handle, _uv_alloc_cb, _uv_read_cb));
  return self;
}

static mrb_value
mrb_uv_read_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_read_stop((uv_stream_t*)&context->handle));
  return self;
}

static mrb_value
mrb_uv_write(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b, arg_data, send_handle_val = mrb_nil_value(), ret;
  uv_buf_t buf;
  mrb_uv_req_t* req;
  uv_write_cb cb = (uv_write_cb)_uv_done_cb;

  mrb_get_args(mrb, "&S|o", &b, &arg_data, &send_handle_val);
  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_set_buf(req, &buf, arg_data);
  if (mrb_nil_p(req->block)) { cb = NULL; }
  if (mrb_nil_p(send_handle_val)) {
    err = uv_write(&req->req.write, (uv_stream_t*)&context->handle, &buf, 1, cb);
  } else {
    mrb_uv_handle *send_handle = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, send_handle_val, &mrb_uv_handle_type);
    if (send_handle->handle.type != UV_NAMED_PIPE && send_handle->handle.type != UV_TCP) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "Unexpected send handle type: %S",
                 mrb_funcall(mrb, send_handle_val, "type", 0));
    }
    err = uv_write2(&req->req.write, (uv_stream_t*)&context->handle, &buf, 1,
                    (uv_stream_t*)&send_handle->handle, cb);
  }
  mrb_uv_req_check_error(mrb, req, err);
  return ret;
}

static mrb_value
mrb_uv_try_write(mrb_state *mrb, mrb_value self)
{
  uv_buf_t buf;
  mrb_value str;
  mrb_uv_handle *context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  int err;

  mrb_get_args(mrb, "S", &str);
  mrb_str_modify(mrb, mrb_str_ptr(str));
  buf = uv_buf_init(RSTRING_PTR(str), RSTRING_LEN(str));
  err = uv_try_write((uv_stream_t*)&context->handle, &buf, 1);
  if (err < 0) {
    mrb_uv_check_error(mrb, err);
  }
  if (err == 0) {
    return symbol_value_lit(mrb, "need_queue");
  } else {
    return mrb_fixnum_value(err);
  }
}

static mrb_value
mrb_uv_shutdown(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&", &b);
  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_shutdown(
      &req->req.shutdown, (uv_stream_t*)&context->handle, (uv_shutdown_cb)_uv_done_cb));
  return ret;
}

static void
_uv_connection_cb(uv_stream_t* uv_h, int status)
{
  mrb_uv_handle *h = (mrb_uv_handle*) uv_h->data;
  mrb_value b = mrb_iv_get(h->mrb, h->instance, mrb_intern_lit(h->mrb, "connection_cb"));
  mrb_value const arg = mrb_uv_create_status(h->mrb, status);
  mrb_yield_argv(h->mrb, b, 1, &arg);
}

static mrb_value
mrb_uv_listen(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_backlog;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_value b = mrb_nil_value();
  uv_connection_cb connection_cb = _uv_connection_cb;

  mrb_get_args(mrb, "&i", &b, &arg_backlog);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "connection_cb"), b);
  mrb_uv_check_error(mrb, uv_listen((uv_stream_t*) &context->handle, arg_backlog, connection_cb));
  return self;
}

static mrb_value
mrb_uv_accept(mrb_state *mrb, mrb_value self)
{
  mrb_value c;
  mrb_uv_handle* context = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_handle* new_context = NULL;

  c = mrb_obj_new(mrb, mrb_class(mrb, self), 0, NULL);
  Data_Get_Struct(mrb, c, &mrb_uv_handle_type, new_context);

  mrb_uv_check_error(mrb, uv_accept((uv_stream_t*) &context->handle, (uv_stream_t*) &new_context->handle));
  mrb_uv_gc_protect(mrb, c);
  return c;
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

#if !MRB_UV_CHECK_VERSION(1, 19, 0)
#define uv_stream_get_write_queue_size(s) ((s)->write_queue_size)
#endif

static mrb_value
mrb_uv_stream_write_queue_size(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle* ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_fixnum_value(uv_stream_get_write_queue_size((uv_stream_t*)&ctx->handle));
}

/*
 * UV::FS::Event
 */
static mrb_value
mrb_uv_fs_event_init(mrb_state *mrb, mrb_value self)
{
  mrb_value l = mrb_nil_value();
  mrb_uv_handle *ctx;
  uv_loop_t *loop;
  mrb_get_args(mrb, "|o", &l);

  loop = get_loop(mrb, &l);
  ctx = mrb_uv_handle_alloc(mrb, UV_FS_EVENT, self, l);
  mrb_uv_check_error(mrb, uv_fs_event_init(loop, (uv_fs_event_t*)&ctx->handle));
  return self;
}

static void
_uv_fs_event_cb(uv_fs_event_t *ev, char const *filename, int events, int status)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)ev->data;
  mrb_state *mrb = ctx->mrb;
  mrb_value args[3];

  mrb_gc_protect(mrb, ctx->block);

  args[0] = mrb_str_new_cstr(mrb, filename);
  switch((enum uv_fs_event)events) {
  case UV_RENAME: args[1] = symbol_value_lit(mrb, "rename"); break;
  case UV_CHANGE: args[1] = symbol_value_lit(mrb, "change"); break;
  default: mrb_assert(FALSE);
  }
  args[2] = mrb_uv_create_status(mrb, status);
  yield_handle_cb(ctx, 3, args);
}

static mrb_value
mrb_uv_fs_event_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  char* path;
  mrb_int flags;
  mrb_value b;

  mrb_get_args(mrb, "&zi", &b, &path, &flags);
  set_handle_cb(ctx, b);
  mrb_uv_check_error(mrb, uv_fs_event_start((uv_fs_event_t*)&ctx->handle, _uv_fs_event_cb, path, flags));
  return self;
}

static mrb_value
mrb_uv_fs_event_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_uv_check_error(mrb, uv_fs_event_stop((uv_fs_event_t*)&ctx->handle));
  return self;
}

static mrb_value
mrb_uv_fs_event_path(mrb_state *mrb, mrb_value self)
{
  char ret[PATH_MAX];
  size_t len = PATH_MAX;
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);

  mrb_uv_check_error(mrb, uv_fs_event_getpath((uv_fs_event_t*)&ctx->handle, ret, &len));
  return mrb_str_new_cstr(mrb, ret);
}

/*
 * UV::Poll
 */
static mrb_value
mrb_uv_poll_init(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx;
  mrb_value fd, l = mrb_nil_value();
  uv_loop_t *loop;
  mrb_get_args(mrb, "o|o", &fd, &l);

  loop = get_loop(mrb, &l);
  ctx = mrb_uv_handle_alloc(mrb, UV_POLL, self, l);
  mrb_uv_check_error(mrb, uv_poll_init(loop, (uv_poll_t*)&ctx->handle, mrb_uv_to_fd(mrb, fd)));
  return self;
}

static mrb_value
mrb_uv_poll_init_socket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, l = mrb_nil_value(), ret;
  mrb_uv_handle *ctx;
  uv_loop_t *loop;
  mrb_get_args(mrb, "o|o", &sock, &l);

  loop = get_loop(mrb, &l);
  ret = mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), NULL, NULL));
  ctx = mrb_uv_handle_alloc(mrb, UV_POLL, ret, l);
  mrb_uv_check_error(mrb, uv_poll_init_socket(loop, (uv_poll_t*)&ctx->handle, mrb_uv_to_socket(mrb, sock)));
  return ret;
}

static void
_uv_poll_cb(uv_poll_t *poll, int status, int events)
{
  mrb_uv_handle *h = (mrb_uv_handle*)poll->data;
  mrb_value args[2] = { mrb_fixnum_value(events), mrb_uv_create_status(h->mrb, status) };
  yield_handle_cb(h, 2, args);
}

static mrb_value
mrb_uv_poll_start(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  mrb_int ev;
  mrb_value b;

  mrb_get_args(mrb, "&i", &b, &ev);
  set_handle_cb(ctx, b);
  return mrb_uv_check_error(mrb, uv_poll_start((uv_poll_t*)&ctx->handle, ev, _uv_poll_cb)), self;
}

static mrb_value
mrb_uv_poll_stop(mrb_state *mrb, mrb_value self)
{
  mrb_uv_handle *ctx = (mrb_uv_handle*)mrb_uv_get_ptr(mrb, self, &mrb_uv_handle_type);
  return mrb_uv_check_error(mrb, uv_poll_stop((uv_poll_t*)&ctx->handle)), self;
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
  struct RClass* _class_uv_check;
  struct RClass* _class_uv_fs_event;
  struct RClass* _class_uv_poll;
  int const ai = mrb_gc_arena_save(mrb);

  _class_uv_handle = mrb_define_module_under(mrb, UV, "Handle");
  mrb_define_method(mrb, _class_uv_handle, "close", mrb_uv_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "closing?", mrb_uv_is_closing, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "active?", mrb_uv_is_active, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "ref", mrb_uv_ref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "unref", mrb_uv_unref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "has_ref?", mrb_uv_has_ref, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "data=", mrb_uv_data_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_handle, "data", mrb_uv_data_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "recv_buffer_size", mrb_uv_recv_buffer_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "recv_buffer_size=", mrb_uv_recv_buffer_size_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_handle, "send_buffer_size", mrb_uv_send_buffer_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "send_buffer_size=", mrb_uv_send_buffer_size_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_handle, "fileno", mrb_uv_fileno, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_handle, "loop", mrb_uv_handle_loop, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 19, 0)
  mrb_define_method(mrb, _class_uv_handle, "type", mrb_uv_handle_get_type, MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, _class_uv_handle, "type_name", mrb_uv_handle_type_name, MRB_ARGS_NONE());

  _class_uv_stream = mrb_define_module_under(mrb, UV, "Stream");
  mrb_include_module(mrb, _class_uv_stream, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_stream, "write", mrb_uv_write, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_stream, "try_write", mrb_uv_try_write, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_stream, "shutdown", mrb_uv_shutdown, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "read_start", mrb_uv_read_start, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "read_stop", mrb_uv_read_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "accept", mrb_uv_accept, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "listen", mrb_uv_listen, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_stream, "readable?", mrb_uv_readable, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "writable?", mrb_uv_writable, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stream, "write_queue_size", mrb_uv_stream_write_queue_size, MRB_ARGS_NONE());

  _class_uv_tty = mrb_define_class_under(mrb, UV, "TTY", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_tty, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_tty, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_tty, "initialize", mrb_uv_tty_init, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tty, "set_mode", mrb_uv_tty_set_mode, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tty, "mode=", mrb_uv_tty_set_mode, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_tty, "reset_mode", mrb_uv_tty_reset_mode, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tty, "get_winsize", mrb_uv_tty_get_winsize, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 2, 0)
  mrb_define_const(mrb, _class_uv_tty, "MODE_NORMAL", mrb_fixnum_value(UV_TTY_MODE_NORMAL));
  mrb_define_const(mrb, _class_uv_tty, "MODE_RAW", mrb_fixnum_value(UV_TTY_MODE_RAW));
  mrb_define_const(mrb, _class_uv_tty, "MODE_IO", mrb_fixnum_value(UV_TTY_MODE_IO));
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_udp = mrb_define_class_under(mrb, UV, "UDP", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_udp, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_udp, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_udp, "initialize", mrb_uv_udp_init, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_udp, "open", mrb_uv_udp_open, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "set_membership", mrb_uv_udp_set_membership, MRB_ARGS_REQ(3));
  mrb_define_method(mrb, _class_uv_udp, "multicast_loop=", mrb_uv_udp_multicast_loop_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "multicast_ttl=", mrb_uv_udp_multicast_ttl_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "multicast_interface=", mrb_uv_udp_multicast_interface_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "broadcast=", mrb_uv_udp_broadcast_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "ttl=", mrb_uv_udp_ttl_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "recv_start", mrb_uv_udp_recv_start, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "recv_stop", mrb_uv_udp_recv_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send", mrb_uv_udp_send4, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "send6", mrb_uv_udp_send6, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_udp, "bind", mrb_uv_udp_bind4, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "bind6", mrb_uv_udp_bind6, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "getsockname", mrb_uv_udp_getsockname, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "sockname", mrb_uv_udp_getsockname, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "try_send", mrb_uv_udp_try_send, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_udp, "send_queue_count", mrb_uv_udp_send_queue_count, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "send_queue_size", mrb_uv_udp_send_queue_size, MRB_ARGS_NONE());
  mrb_define_const(mrb, _class_uv_udp, "LEAVE_GROUP", mrb_fixnum_value(UV_LEAVE_GROUP));
  mrb_define_const(mrb, _class_uv_udp, "JOIN_GROUP", mrb_fixnum_value(UV_JOIN_GROUP));
#if MRB_UV_CHECK_VERSION(1, 27, 0)
  mrb_define_method(mrb, _class_uv_udp, "peername", mrb_uv_udp_get_peername, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_udp, "connect", mrb_uv_udp_connect, MRB_ARGS_REQ(1));
#endif
#if MRB_UV_CHECK_VERSION(1, 32, 0)
  mrb_define_method(mrb, _class_uv_udp, "set_source_membership", mrb_uv_udp_set_source_membership, MRB_ARGS_REQ(3));
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_process = mrb_define_class_under(mrb, UV, "Process", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_process, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_process, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_process, "initialize", mrb_uv_process_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "spawn", mrb_uv_process_spawn, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe=", mrb_uv_process_stdout_pipe_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdout_pipe", mrb_uv_process_stdout_pipe_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe=", mrb_uv_process_stdin_pipe_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stdin_pipe", mrb_uv_process_stdin_pipe_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe=", mrb_uv_process_stderr_pipe_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_process, "stderr_pipe", mrb_uv_process_stderr_pipe_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "kill", mrb_uv_process_kill, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "pid", mrb_uv_process_pid, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 23, 0)
  mrb_define_method(mrb, _class_uv_process, "priority", mrb_uv_process_get_priority, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_process, "priority=", mrb_uv_process_set_priority, MRB_ARGS_REQ(1));
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_signal = mrb_define_class_under(mrb, UV, "Signal", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_signal, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_signal, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_signal, "initialize", mrb_uv_signal_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_signal, "start", mrb_uv_signal_start, MRB_ARGS_REQ(1));
#if MRB_UV_CHECK_VERSION(1, 12, 0)
  mrb_define_method(mrb, _class_uv_signal, "start_oneshot", mrb_uv_signal_start_oneshot, MRB_ARGS_REQ(1));
#endif
  mrb_define_method(mrb, _class_uv_signal, "stop", mrb_uv_signal_stop, MRB_ARGS_NONE());
  mrb_define_const(mrb, _class_uv_signal, "SIGINT", mrb_fixnum_value(SIGINT));
#ifdef SIGUSR1
  mrb_define_const(mrb, _class_uv_signal, "SIGUSR1", mrb_fixnum_value(SIGUSR1));
#endif
#ifdef SIGUSR2
  mrb_define_const(mrb, _class_uv_signal, "SIGUSR2", mrb_fixnum_value(SIGUSR2));
#endif
#ifdef SIGPROF
  mrb_define_const(mrb, _class_uv_signal, "SIGPROF", mrb_fixnum_value(SIGPROF));
#endif
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
  mrb_define_method(mrb, _class_uv_fs_poll, "initialize", mrb_uv_fs_poll_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_poll, "start", mrb_uv_fs_poll_start, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs_poll, "stop", mrb_uv_fs_poll_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_poll, "path", mrb_uv_fs_poll_getpath, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_timer = mrb_define_class_under(mrb, UV, "Timer", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_timer, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_timer, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_timer, "initialize", mrb_uv_timer_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_timer, "again", mrb_uv_timer_again, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "repeat", mrb_uv_timer_repeat, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_timer, "repeat=", mrb_uv_timer_repeat_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_timer, "start", mrb_uv_timer_start, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_timer, "stop", mrb_uv_timer_stop, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_idle = mrb_define_class_under(mrb, UV, "Idle", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_idle, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_idle, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_idle, "initialize", mrb_uv_idle_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "start", mrb_uv_idle_start, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_idle, "stop", mrb_uv_idle_stop, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_async = mrb_define_class_under(mrb, UV, "Async", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_async, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_async, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_async, "initialize", mrb_uv_async_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_async, "send", mrb_uv_async_send, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_prepare = mrb_define_class_under(mrb, UV, "Prepare", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_prepare, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_prepare, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_prepare, "initialize", mrb_uv_prepare_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_prepare, "start", mrb_uv_prepare_start, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_prepare, "stop", mrb_uv_prepare_stop, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_tcp = mrb_define_class_under(mrb, UV, "TCP", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_tcp, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_tcp, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_tcp, "initialize", mrb_uv_tcp_init, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_tcp, "open", mrb_uv_tcp_open, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "connect", mrb_uv_tcp_connect4, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "connect6", mrb_uv_tcp_connect6, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_tcp, "bind", mrb_uv_tcp_bind4, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "bind6", mrb_uv_tcp_bind6, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "simultaneous_accepts=", mrb_uv_tcp_simultaneous_accepts_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "keepalive=", mrb_uv_tcp_keepalive_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "nodelay=", mrb_uv_tcp_nodelay_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_tcp, "simultaneous_accepts?", mrb_uv_tcp_simultaneous_accepts_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "keepalive?", mrb_uv_tcp_keepalive_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "keepalive_delay", mrb_uv_tcp_keepalive_delay, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "nodelay?", mrb_uv_tcp_nodelay_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "getpeername", mrb_uv_tcp_getpeername, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "getsockname", mrb_uv_tcp_getsockname, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "peername", mrb_uv_tcp_getpeername, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_tcp, "sockname", mrb_uv_tcp_getsockname, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 32, 0)
  mrb_define_method(mrb, _class_uv_tcp, "close_reset", mrb_uv_tcp_close_reset, MRB_ARGS_BLOCK());
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_pipe = mrb_define_class_under(mrb, UV, "Pipe", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_pipe, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_pipe, _class_uv_stream);
  mrb_define_method(mrb, _class_uv_pipe, "initialize", mrb_uv_pipe_init, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_pipe, "open", mrb_uv_pipe_open, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "connect", mrb_uv_pipe_connect, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_pipe, "bind", mrb_uv_pipe_bind, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_pipe, "pending_instances=", mrb_uv_pipe_pending_instances, MRB_ARGS_REQ(1));
#if MRB_UV_CHECK_VERSION(1, 3, 0)
  mrb_define_method(mrb, _class_uv_pipe, "peername", mrb_uv_pipe_getpeername, MRB_ARGS_NONE());
#endif
  mrb_define_method(mrb, _class_uv_pipe, "sockname", mrb_uv_pipe_getsockname, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 16, 0)
  mrb_define_method(mrb, _class_uv_pipe, "chmod", mrb_uv_pipe_chmod, MRB_ARGS_REQ(1));
#endif
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_check = mrb_define_class_under(mrb, UV, "Check", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_check, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_check, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_check, "initialize", mrb_uv_check_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_check, "start", mrb_uv_check_start, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_check, "stop", mrb_uv_check_stop, MRB_ARGS_NONE());

  _class_uv_fs_event = mrb_define_class_under(mrb, mrb_class_get_under(mrb, UV, "FS"), "Event", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_fs_event, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_fs_event, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_fs_event, "initialize", mrb_uv_fs_event_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_fs_event, "start", mrb_uv_fs_event_start, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs_event, "stop", mrb_uv_fs_event_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs_event, "path", mrb_uv_fs_event_path, MRB_ARGS_NONE());
  mrb_define_const(mrb, _class_uv_fs_event, "WATCH_ENTRY", mrb_fixnum_value(UV_FS_EVENT_WATCH_ENTRY));
  mrb_define_const(mrb, _class_uv_fs_event, "STAT", mrb_fixnum_value(UV_FS_EVENT_STAT));
  mrb_define_const(mrb, _class_uv_fs_event, "RECURSIVE", mrb_fixnum_value(UV_FS_EVENT_RECURSIVE));
  mrb_define_const(mrb, _class_uv_fs_event, "CHANGE", symbol_value_lit(mrb, "change"));
  mrb_define_const(mrb, _class_uv_fs_event, "RENAME", symbol_value_lit(mrb, "rename"));

  _class_uv_poll = mrb_define_class_under(mrb, UV, "Poll", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_poll, MRB_TT_DATA);
  mrb_include_module(mrb, _class_uv_poll, _class_uv_handle);
  mrb_define_method(mrb, _class_uv_poll, "initialize", mrb_uv_poll_init, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, _class_uv_poll, "create_from_socket", mrb_uv_poll_init_socket, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_poll, "start", mrb_uv_poll_start, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_poll, "stop", mrb_uv_poll_stop, MRB_ARGS_NONE());
  mrb_define_const(mrb, _class_uv_poll, "READABLE", mrb_fixnum_value(UV_READABLE));
  mrb_define_const(mrb, _class_uv_poll, "WRITABLE", mrb_fixnum_value(UV_WRITABLE));
#if MRB_UV_CHECK_VERSION(1, 9, 0)
  mrb_define_const(mrb, _class_uv_poll, "DISCONNECT", mrb_fixnum_value(UV_DISCONNECT));
#endif
#if MRB_UV_CHECK_VERSION(1, 14, 0)
  mrb_define_const(mrb, _class_uv_poll, "PRIORITIZED", mrb_fixnum_value(UV_PRIORITIZED));
#endif

  mrb_define_const(mrb, UV, "READABLE", mrb_fixnum_value(UV_READABLE));
  mrb_define_const(mrb, UV, "WRITABLE", mrb_fixnum_value(UV_WRITABLE));
#if MRB_UV_CHECK_VERSION(1, 21, 0)
  mrb_define_const(mrb, UV, "OVERLAPPED_PIPE", mrb_fixnum_value(UV_OVERLAPPED_PIPE));
#endif
}
