#include "mrb_uv.h"

#define _GNU_SOURCE
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#define PATH_MAX MAX_PATH
#endif

#ifndef MRUBY_VERSION
#define mrb_module_get mrb_class_get
#endif

/*********************************************************
 * main
 *********************************************************/
static mrb_value
mrb_uv_gc(mrb_state *mrb, mrb_value self)
{
  int ai = mrb_gc_arena_save(mrb);
  struct RClass* _class_uv = mrb_module_get(mrb, "UV");
  mrb_value uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "$GC"));
  int i, l = RARRAY_LEN(uv_gc_table);
  for (i = 0; i < l; i++) {
    if (DATA_PTR(mrb_ary_entry(uv_gc_table, i)) == NULL) {
      mrb_funcall(mrb, uv_gc_table, "delete_at", 1, mrb_fixnum_value(i));
      i--;
      l--;
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
  mrb_value proc = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "$ONCE"));
  mrb_yield_argv(mrb, proc, 0, NULL);
}

static mrb_value
mrb_uv_once(mrb_state *mrb, mrb_value self)
{
  mrb_value b = mrb_nil_value();
  mrb_get_args(mrb, "&", &b);
  uv_once_t guard;
  struct RClass* _class_uv = mrb_module_get(mrb, "UV");
  mrb_define_const(mrb, _class_uv, "$ONCE", b);
  uv_once(&guard, _uv_once_cb);
  return mrb_nil_value();
}
*/

mrb_value
mrb_uv_data_get(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "data"));
}

mrb_value
mrb_uv_data_set(mrb_state *mrb, mrb_value self)
{
  mrb_value arg;
  mrb_get_args(mrb, "o", &arg);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "data"), arg);
  return mrb_nil_value();
}

/*********************************************************
 * UV::Loop
 *********************************************************/
static void
mrb_uv_loop_free(mrb_state *mrb, void *p)
{
  if (p || p != uv_default_loop()) {
    uv_loop_close((uv_loop_t*)p);
    mrb_free(mrb, p);
  }
}

const struct mrb_data_type mrb_uv_loop_type = {
  "uv_loop", mrb_uv_loop_free
};

static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  mrb_value c;

  struct RClass* _class_uv = mrb_module_get(mrb, "UV");
  struct RClass* _class_uv_loop = mrb_class_get_under(mrb, _class_uv, "Loop");
  c = mrb_obj_new(mrb, _class_uv_loop, 0, NULL);

  DATA_PTR(self) = uv_default_loop();
  DATA_TYPE(self) = &mrb_uv_loop_type;
  return c;
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *l = (uv_loop_t*)mrb_malloc(mrb, sizeof(uv_loop_t));
  int err = uv_loop_init(l);
  if(err < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  DATA_PTR(self) = l;
  DATA_TYPE(self) = &mrb_uv_loop_type;
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  int err;
  uv_loop_t* loop = NULL;
  mrb_int arg_mode = UV_RUN_DEFAULT;

  Data_Get_Struct(mrb, self, &mrb_uv_loop_type, loop);

  mrb_get_args(mrb, "|i", &arg_mode);
  err = uv_run(loop, arg_mode);
  if (err != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_delete(mrb_state *mrb, mrb_value self)
{
  uv_loop_t* loop = NULL;

  Data_Get_Struct(mrb, self, &mrb_uv_loop_type, loop);

  uv_loop_close(loop);
  mrb_free(mrb, loop);
  DATA_PTR(self) = NULL;
  return mrb_nil_value();
}

/*********************************************************
 * UV::Ip4Addr
 *********************************************************/
static void
uv_ip4addr_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, p);
}

const struct mrb_data_type mrb_uv_ip4addr_type = {
  "uv_ip4addr", uv_ip4addr_free,
};

/* NOTE: this type is internally used for instances where a
 * sockaddr is owned by libuv (such as during callbacks),
 * therefore we don't want mruby to free the pointer during
 * garbage collection */
const struct mrb_data_type mrb_uv_ip4addr_nofree_type = {
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
  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_ip4addr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
  return mrb_obj_new(mrb, _class_uv_ip4addr, argc, argv);
}

static mrb_value
mrb_uv_ip4addr_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_host = mrb_nil_value(),  arg_port = mrb_nil_value();
  struct sockaddr_in vaddr;
  struct sockaddr_in *addr = NULL, *paddr = NULL;

  mrb_get_args(mrb, "o|o", &arg_host, &arg_port);
  if (mrb_type(arg_host) == MRB_TT_STRING && !mrb_nil_p(arg_port) && mrb_fixnum_p(arg_port)) {
    int err = uv_ip4_addr((const char*) RSTRING_PTR(arg_host), mrb_fixnum(arg_port), &vaddr);
    if (err != 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
    }
    addr = (struct sockaddr_in*) mrb_malloc(mrb, sizeof(struct sockaddr_in));
    memcpy(addr, &vaddr, sizeof(struct sockaddr_in));
  } else if (mrb_type(arg_host) == MRB_TT_DATA) {
    if (DATA_TYPE(arg_host) == &mrb_uv_ip4addr_nofree_type) {
      paddr = (struct sockaddr_in *) DATA_PTR(arg_host);
    }
    else {
      Data_Get_Struct(mrb, arg_host, &mrb_uv_ip4addr_type, paddr);
    }
    addr = (struct sockaddr_in*) mrb_malloc(mrb, sizeof(struct sockaddr_in));
    memcpy(addr, paddr, sizeof(struct sockaddr_in));
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  DATA_PTR(self) = addr;
  DATA_TYPE(self) = &mrb_uv_ip4addr_type;
  return self;
}

static mrb_value
mrb_uv_ip4addr_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value str = mrb_funcall(mrb, self, "sin_addr", 0);
  mrb_str_cat2(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_funcall(mrb, self, "sin_port", 0));
  return str;
}

static mrb_value
mrb_uv_ip4addr_sin_addr(mrb_state *mrb, mrb_value self)
{
  int err;
  struct sockaddr_in* addr = NULL;
  char name[256];

  Data_Get_Struct(mrb, self, &mrb_uv_ip4addr_type, addr);
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
  struct sockaddr_in* addr = NULL;
  Data_Get_Struct(mrb, self, &mrb_uv_ip4addr_type, addr);
  return mrb_fixnum_value(htons(addr->sin_port));
}

/*********************************************************
 * UV::Ip6Addr
 *********************************************************/
static void
uv_ip6addr_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, p);
}

const struct mrb_data_type mrb_uv_ip6addr_type = {
  "uv_ip6addr", uv_ip6addr_free,
};

/* NOTE: this type is internally used for instances where a
 * sockaddr is owned by libuv (such as during callbacks),
 * therefore we don't want mruby to free the pointer during
 * garbage collection */
const struct mrb_data_type mrb_uv_ip6addr_nofree_type = {
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
  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_ip6addr = mrb_class_get_under(mrb, _class_uv, "Ip6Addr");
  return mrb_obj_new(mrb, _class_uv_ip6addr, argc, argv);
}

static mrb_value
mrb_uv_ip6addr_init(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_host = mrb_nil_value(), arg_port = mrb_nil_value();
  struct sockaddr_in6 vaddr;
  struct sockaddr_in6 *addr = NULL, *paddr = NULL;

  mrb_get_args(mrb, "o|o", &arg_host, &arg_port);
  if (mrb_type(arg_host) == MRB_TT_STRING && !mrb_nil_p(arg_port) && mrb_fixnum_p(arg_port)) {
    int err = uv_ip6_addr((const char*) RSTRING_PTR(arg_host), mrb_fixnum(arg_port), &vaddr);
    if (err != 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
    }
    addr = (struct sockaddr_in6*) mrb_malloc(mrb, sizeof(struct sockaddr_in6));
    memcpy(addr, &vaddr, sizeof(struct sockaddr_in6));
  } else if (mrb_type(arg_host) == MRB_TT_DATA) {
    if (DATA_TYPE(arg_host) == &mrb_uv_ip6addr_nofree_type) {
      paddr = (struct sockaddr_in6 *) DATA_PTR(arg_host);
    }
    else {
      Data_Get_Struct(mrb, arg_host, &mrb_uv_ip6addr_type, paddr);
    }
    addr = (struct sockaddr_in6*) mrb_malloc(mrb, sizeof(struct sockaddr_in6));
    memcpy(addr, paddr, sizeof(struct sockaddr_in6));
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  DATA_PTR(self) = addr;
  DATA_TYPE(self) = &mrb_uv_ip6addr_type;
  return self;
}

static mrb_value
mrb_uv_ip6addr_to_s(mrb_state *mrb, mrb_value self)
{
  mrb_value str = mrb_funcall(mrb, self, "sin_addr", 0);
  mrb_str_cat2(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_funcall(mrb, self, "sin_port", 0));
  return str;
}

static mrb_value
mrb_uv_ip6addr_sin_addr(mrb_state *mrb, mrb_value self)
{
  int err;
  struct sockaddr_in6* addr = NULL;
  char name[256];

  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
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
  struct sockaddr_in6* addr = NULL;
  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
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
  mrb_free(mrb, p);
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
    struct RClass* _class_uv = mrb_module_get(mrb, "UV");
    struct RClass* _class_uv_addrinfo = mrb_class_get_under(mrb, _class_uv, "Addrinfo");
    c = mrb_obj_new(mrb, _class_uv_addrinfo, 0, NULL);
    DATA_PTR(c) = addr;
    DATA_TYPE(c) = &uv_addrinfo_type;
    addr->addr = res;
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
  mrb_uv_addrinfo* addr;
  uv_getaddrinfo_t* req;
  int ret;

  mrb_get_args(mrb, "SS&", &node, &service, &b);

  addr = (mrb_uv_addrinfo*) mrb_malloc(mrb, sizeof(mrb_uv_addrinfo));
  memset(addr, 0, sizeof(mrb_uv_addrinfo));
  addr->mrb = mrb;
  addr->proc = b;

  if (mrb_nil_p(b)) {
    getaddrinfo_cb = NULL;
  }

  req = (uv_getaddrinfo_t*) mrb_malloc(mrb, sizeof(uv_getaddrinfo_t));
  memset(req, 0, sizeof(uv_getaddrinfo_t));
  req->data = addr;
  ret = uv_getaddrinfo(
    uv_default_loop(),
    req,
    getaddrinfo_cb,
    RSTRING_PTR(node),
    RSTRING_PTR(service),
    NULL);
  return mrb_fixnum_value(ret);
}

static mrb_value
mrb_uv_addrinfo_flags(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->addr->ai_flags);
}

static mrb_value
mrb_uv_addrinfo_family(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->addr->ai_family);
}

static mrb_value
mrb_uv_addrinfo_socktype(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->addr->ai_socktype);
}

static mrb_value
mrb_uv_addrinfo_protocol(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);
  return mrb_fixnum_value(addr->addr->ai_protocol);
}

static mrb_value
mrb_uv_addrinfo_addr(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  struct RClass* _class_uv;
  mrb_value c = mrb_nil_value();
  mrb_value args[1];

  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);

  _class_uv = mrb_module_get(mrb, "UV");

  switch (addr->addr->ai_family) {
  case AF_INET:
    {
      struct RClass* _class_uv_ip4addr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
      struct sockaddr_in* saddr = (struct sockaddr_in*)mrb_malloc(mrb, sizeof(struct sockaddr_in));
      *saddr = *(struct sockaddr_in*)addr->addr->ai_addr;
      args[0] = mrb_obj_value(
        Data_Wrap_Struct(mrb, mrb->object_class,
        &mrb_uv_ip4addr_type, (void*) saddr));
      c = mrb_obj_new(mrb, _class_uv_ip4addr, 1, args);
    }
    break;
  case AF_INET6:
    {
      struct RClass* _class_uv_ip6addr = mrb_class_get_under(mrb, _class_uv, "Ip6Addr");
      struct sockaddr_in6* saddr = (struct sockaddr_in6*)mrb_malloc(mrb, sizeof(struct sockaddr_in6));
      *saddr = *(struct sockaddr_in6*)addr->addr->ai_addr;
      args[0] = mrb_obj_value(
        Data_Wrap_Struct(mrb, mrb->object_class,
        &mrb_uv_ip6addr_type, (void*) saddr));
      c = mrb_obj_new(mrb, _class_uv_ip6addr, 1, args);
    }
    break;
  }
  return c;
}

static mrb_value
mrb_uv_addrinfo_canonname(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);
  return mrb_str_new_cstr(mrb,
    addr->addr->ai_canonname ? addr->addr->ai_canonname : "");
}

static mrb_value
mrb_uv_addrinfo_next(mrb_state *mrb, mrb_value self)
{
  mrb_uv_addrinfo* addr = NULL;
  Data_Get_Struct(mrb, self, &uv_addrinfo_type, addr);

  if (addr->addr->ai_next) {
    struct RClass* _class_uv = mrb_module_get(mrb, "UV");
    struct RClass* _class_uv_ip4addr = mrb_class_get_under(mrb, _class_uv, "Addrinfo");

    mrb_value c = mrb_obj_new(mrb, _class_uv_ip4addr, 0, NULL);
    DATA_PTR(c) = addr->addr->ai_next;
    DATA_TYPE(c) = &uv_addrinfo_type;
    return c;
  }
  return mrb_nil_value();
}

/*********************************************************
 * UV::FS
 *********************************************************/
typedef struct {
  mrb_state* mrb;
  mrb_value instance;
  uv_file fd;
} mrb_uv_file;

static void
mrb_uv_fs_free(mrb_state *mrb, void *p)
{
  mrb_uv_file *ctx = (mrb_uv_file*)p;
  if (ctx) {
    uv_fs_t req;
    req.data = ctx;
    uv_fs_close(uv_default_loop(), &req, ctx->fd, NULL);
    mrb_free(mrb, ctx);
  }
}

static const struct mrb_data_type mrb_uv_file_type = {
  "uv_file", mrb_uv_fs_free
};

static void
_uv_fs_open_cb(uv_fs_t* req)
{
  mrb_uv_file *context = (mrb_uv_file*)req->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  if (req->result < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(req->result));
  }
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "fs_cb"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    context->fd = req->result;
    args[0] = mrb_fixnum_value(req->result);
    mrb_yield_argv(mrb, proc, 1, args);
  }
  uv_fs_req_cleanup(req);
  mrb_free(mrb, req);
}

static void
_uv_fs_cb(uv_fs_t* req)
{
  mrb_uv_file* context = (mrb_uv_file*) req->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  uv_fs_t close_req;
  if (req->result < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(req->result));
  }
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "fs_cb"));

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
      uv_fs_close(uv_default_loop(), &close_req, context->fd, NULL);
      goto leave;
    }
    if (!mrb_nil_p(proc)) {
       mrb_value args[1];
       args[0] = mrb_fixnum_value(req->result);
       mrb_yield_argv(mrb, proc, 1, args);
    }
    if (req->fs_type == UV_FS_CLOSE) {
      mrb_free(mrb, context);
      DATA_PTR(context->instance) = NULL;
    }
    break;
  }
leave:
  uv_fs_req_cleanup(req);
  mrb_free(mrb, req);
}

static mrb_value
mrb_uv_fs_fd(mrb_state *mrb, mrb_value self)
{
  mrb_uv_file *ctx;
  Data_Get_Struct(mrb, self, &mrb_uv_file_type, ctx);
  return mrb_fixnum_value(ctx->fd);
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
  mrb_uv_file* context;
  uv_fs_t* req;
  int ai;
  mrb_value uv_gc_table;

  mrb_get_args(mrb, "&Sii", &b, &arg_filename, &arg_flags, &arg_mode);

  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_fs = mrb_class_get_under(mrb, _class_uv, "FS");
  c = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, _class_uv_fs));

  context = (mrb_uv_file*)mrb_malloc(mrb, sizeof(mrb_uv_file));
  context->mrb = mrb;
  context->instance = c;
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "fs_cb"), b);

  DATA_PTR(c) = context;
  DATA_TYPE(c) = &mrb_uv_file_type;

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  context->fd = uv_fs_open(uv_default_loop(), req, RSTRING_PTR(arg_filename), arg_flags, arg_mode, fs_cb);
  if (context->fd < 0) {
    mrb_free(mrb, req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(context->fd));
  }

  ai = mrb_gc_arena_save(mrb);
  uv_gc_table = mrb_const_get(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "$GC"));
  mrb_ary_push(mrb, uv_gc_table, c);
  mrb_gc_arena_restore(mrb, ai);
  return c;
}

static mrb_value
mrb_uv_fs_close(mrb_state *mrb, mrb_value self)
{
  mrb_uv_file* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;

  Data_Get_Struct(mrb, self, &mrb_uv_file_type, context);

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  uv_fs_close(uv_default_loop(), req, context->fd, fs_cb);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_fs_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value();
  mrb_int arg_length = -1;
  mrb_int arg_offset = 0;
  mrb_uv_file* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;
  int r;
  uv_buf_t buf;

  Data_Get_Struct(mrb, self, &mrb_uv_file_type, context);

  mrb_get_args(mrb, "&S|ii", &b, &arg_data, &arg_offset, &arg_length);

  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  if (arg_length == -1)
    arg_length = RSTRING_LEN(arg_data);
  if (arg_offset < 0)
    arg_offset = 0;
  buf.base = RSTRING_PTR(arg_data);
  buf.len = arg_length;
  r = uv_fs_write(uv_default_loop(), req, context->fd, &buf, 1, arg_offset, fs_cb);
  if (r < 0) {
    mrb_free(mrb, req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(r));
  }
  return mrb_fixnum_value(r);
}

static mrb_value
mrb_uv_fs_read(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_length = BUFSIZ;
  mrb_int arg_offset = 0;
  mrb_uv_file* context = NULL;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_buf_t buf;
  int len;
  uv_fs_t* req;
  int ai;
  mrb_value str;

  Data_Get_Struct(mrb, self, &mrb_uv_file_type, context);

  mrb_get_args(mrb, "&|i|i", &b, &arg_length, &arg_offset);

  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  buf.base = mrb_malloc(mrb, arg_length);
  buf.len = arg_length;
  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  if (!req) {
    mrb_free(mrb, buf.base);
  }
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  len = uv_fs_read(uv_default_loop(), req, context->fd, &buf, 1, arg_offset, fs_cb);
  if (len < 0) {
    mrb_free(mrb, buf.base);
    mrb_free(mrb, req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(len));
  }
  ai = mrb_gc_arena_save(mrb);
  str = mrb_str_new(mrb, buf.base, len);
  mrb_gc_arena_restore(mrb, ai);
  mrb_free(mrb, buf.base);
  return str;
}

static mrb_value
mrb_uv_fs_unlink(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_unlink(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S|i", &b, &arg_path, &arg_mode);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_mkdir(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_mode, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_rmdir(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_flags);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_readdir(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_flags, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_stat(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fstat(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_lstat(uv_default_loop(), req, RSTRING_PTR(arg_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&SS", &b, &arg_path, &arg_new_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_rename(uv_default_loop(), req, RSTRING_PTR(arg_path), RSTRING_PTR(arg_new_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fsync(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_file);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_fdatasync(uv_default_loop(), req, arg_file, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&ii", &b, &arg_file, &arg_offset);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_ftruncate(uv_default_loop(), req, arg_file, arg_offset, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  // TODO: accept UV::FS object also.
  mrb_get_args(mrb, "&iiii", &b, &arg_infd, &arg_outfd, &arg_offset, &arg_length);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_sendfile(uv_default_loop(), req, arg_infd, arg_outfd, arg_offset, arg_length, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_mode);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_chmod(uv_default_loop(), req, RSTRING_PTR(arg_path), arg_mode, fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
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
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&SS", &b, &arg_path, &arg_new_path);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  } else {
    memset(&context, 0, sizeof(mrb_uv_file));
    context.mrb = mrb;
    context.instance = self;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_link(uv_default_loop(), req, RSTRING_PTR(arg_path), RSTRING_PTR(arg_new_path), fs_cb);
  if (err != 0) {
    mrb_free(mrb, req);
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(err));
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_guess_handle(mrb_state *mrb, mrb_value self)
{
  mrb_int fd;
  mrb_get_args(mrb, "i", &fd);

  uv_handle_type h = uv_guess_handle(fd);

  if(h < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_strerror(h));
  }

  switch(h) {
  case UV_FILE: return mrb_symbol_value(mrb_intern_lit(mrb, "file"));

#define XX(t, l) case UV_ ## t: return mrb_symbol_value(mrb_intern_lit(mrb, #l));
  UV_HANDLE_TYPE_MAP(XX)
#undef XX

  default:
  case UV_UNKNOWN_HANDLE:
    return mrb_symbol_value(mrb_intern_lit(mrb, "unknown"));
  }
}

/*********************************************************
 * register
 *********************************************************/

void
mrb_mruby_uv_gem_init(mrb_state* mrb) {
  int ai = mrb_gc_arena_save(mrb);

  struct RClass* _class_uv;
  struct RClass* _class_uv_loop;
  struct RClass* _class_uv_addrinfo;
  struct RClass* _class_uv_ip4addr;
  struct RClass* _class_uv_ip6addr;
  struct RClass* _class_uv_fs;
  mrb_value uv_gc_table;

  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_module_function(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  //mrb_define_module_function(mrb, _class_uv, "once", mrb_uv_once, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "ip6_addr", mrb_uv_ip6_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "getaddrinfo", mrb_uv_getaddrinfo, ARGS_REQ(3));
  mrb_define_module_function(mrb, _class_uv, "gc", mrb_uv_gc, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "guess_handle", mrb_uv_guess_handle, MRB_ARGS_REQ(1));

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
  MRB_SET_INSTANCE_TT(_class_uv_loop, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_loop, "initialize", mrb_uv_loop_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run", mrb_uv_loop_run, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_delete, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_addrinfo = mrb_define_class_under(mrb, _class_uv, "Addrinfo", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_addrinfo, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_addrinfo, "flags", mrb_uv_addrinfo_flags, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "family", mrb_uv_addrinfo_family, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "socktype", mrb_uv_addrinfo_socktype, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "protocol", mrb_uv_addrinfo_protocol, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "addr", mrb_uv_addrinfo_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "canonname", mrb_uv_addrinfo_canonname, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "next", mrb_uv_addrinfo_next, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip4addr = mrb_define_class_under(mrb, _class_uv, "Ip4Addr", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_ip4addr, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_ip4addr, "initialize", mrb_uv_ip4addr_init, ARGS_REQ(1) | ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip4addr, "to_s", mrb_uv_ip4addr_to_s, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_addr", mrb_uv_ip4addr_sin_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_port", mrb_uv_ip4addr_sin_port, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip6addr = mrb_define_class_under(mrb, _class_uv, "Ip6Addr", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_ip6addr, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_ip6addr, "initialize", mrb_uv_ip6addr_init, ARGS_REQ(1) | ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip6addr, "to_s", mrb_uv_ip6addr_to_s, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_addr", mrb_uv_ip6addr_sin_addr, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_port", mrb_uv_ip6addr_sin_port, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_fs = mrb_define_class_under(mrb, _class_uv, "FS", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_fs, MRB_TT_DATA);
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
  mrb_define_module_function(mrb, _class_uv_fs, "close", mrb_uv_fs_close, ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs, "write", mrb_uv_fs_write, ARGS_REQ(1) | ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_fs, "read", mrb_uv_fs_read, ARGS_REQ(0) | ARGS_OPT(2));
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

  /* TODO
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
  uv_cond_init
  uv_cond_destroy
  uv_cond_signal
  uv_cond_broadcast
  uv_cond_wait
  uv_cond_timedwait
  */

  mrb_mruby_uv_gem_init_handle(mrb, _class_uv);
  mrb_mruby_uv_gem_init_thread(mrb, _class_uv);
  mrb_mruby_uv_gem_init_dl(mrb, _class_uv);

  uv_gc_table = mrb_ary_new(mrb);
  mrb_define_const(mrb, _class_uv, "$GC", uv_gc_table);
}

void
mrb_mruby_uv_gem_final(mrb_state* mrb) {
  mrb_uv_gc(mrb, mrb_nil_value());
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
