#include "mruby/uv.h"
#include "mrb_uv.h"

/*********************************************************
 * main
 *********************************************************/

mrb_value
mrb_uv_gc_table_get(mrb_state *mrb)
{
  return mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "UV")), mrb_intern_lit(mrb, "$GC"));
}

void
mrb_uv_gc_table_clean(mrb_state *mrb)
{
  int i, new_i;
  mrb_value t = mrb_uv_gc_table_get(mrb);
  mrb_value *ary = RARRAY_PTR(t);
  for (i = 0, new_i = 0; i < RARRAY_LEN(t); ++i) {
    if (DATA_PTR(ary[i])) {
      ary[new_i++] = ary[i];
    }
  }
  RARRAY_LEN(t) = new_i;
}

void
mrb_uv_gc_protect(mrb_state *mrb, mrb_value v)
{
  mrb_assert(mrb_type(v) == MRB_TT_DATA);
  mrb_ary_push(mrb, mrb_uv_gc_table_get(mrb), v);
}

static mrb_value
mrb_uv_gc(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_gc_table_clean(mrb), self;
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
  uv_loop_t *l = (uv_loop_t*)p;
  if (l && l != uv_default_loop()) {
    int err = uv_loop_close(l);
    if (err < 0) {
      mrb_uv_error(mrb, err);
    }
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
    mrb_uv_error(mrb, err);
  }
  DATA_PTR(self) = l;
  DATA_TYPE(self) = &mrb_uv_loop_type;
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  int err;
  uv_loop_t* loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  mrb_int arg_mode = UV_RUN_DEFAULT;

  mrb_get_args(mrb, "|i", &arg_mode);
  err = uv_run(loop, arg_mode);
  if (err != 0) {
    mrb_uv_error(mrb, err);
  }
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_close(mrb_state *mrb, mrb_value self)
{
  uv_loop_t* loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  int err;

  err = uv_loop_close(loop);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  mrb_free(mrb, loop);
  DATA_PTR(self) = NULL;
  return mrb_nil_value();
}

static mrb_value
mrb_uv_loop_alive(mrb_state *mrb, mrb_value self)
{
  uv_loop_t* loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return mrb_bool_value(uv_loop_alive(loop));
}

static mrb_value
mrb_uv_stop(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return uv_stop(loop), self;
}

static mrb_value
mrb_uv_update_time(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return uv_update_time(loop), self;
}

static mrb_value
mrb_uv_backend_fd(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return mrb_fixnum_value(uv_backend_fd(loop));
}

static mrb_value
mrb_uv_backend_timeout(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return mrb_fixnum_value(uv_backend_timeout(loop));
}

static mrb_value
mrb_uv_loadavg(mrb_state *mrb, mrb_value self)
{
  mrb_value ret = mrb_ary_new_capa(mrb, 3);
  double avg[3];
  uv_loadavg(avg);
  mrb_ary_push(mrb, ret, mrb_float_value(mrb, avg[0]));
  mrb_ary_push(mrb, ret, mrb_float_value(mrb, avg[1]));
  mrb_ary_push(mrb, ret, mrb_float_value(mrb, avg[2]));
  return ret;
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
      mrb_uv_error(mrb, err);
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
    mrb_uv_error(mrb, err);
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
      mrb_uv_error(mrb, err);
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
    mrb_uv_error(mrb, err);
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

static mrb_value
mrb_uv_guess_handle(mrb_state *mrb, mrb_value self)
{
  mrb_int fd;
  uv_handle_type h;
  mrb_get_args(mrb, "i", &fd);

  h = uv_guess_handle(fd);

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

static mrb_value
mrb_uv_exepath(mrb_state *mrb, mrb_value self)
{
  char buf[PATH_MAX];
  size_t s = sizeof(buf);
  int err = uv_exepath(buf, &s);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  return mrb_str_new(mrb, buf, s);
}

static mrb_value
mrb_uv_cwd(mrb_state *mrb, mrb_value self)
{
  char buf[PATH_MAX];
  size_t s = sizeof(buf);
  int err = uv_cwd(buf, &s);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  return mrb_str_new(mrb, buf, s);
}

static mrb_value
mrb_uv_chdir(mrb_state *mrb, mrb_value self)
{
  int err;
  char *z;
  mrb_get_args(mrb, "z", &z);
  err = uv_chdir(z);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_kill(mrb_state *mrb, mrb_value self)
{
  mrb_int pid, sig;
  int err;
  mrb_get_args(mrb, "ii", &pid, &sig);
  err = uv_kill(pid, sig);
  if(err < 0) {
    mrb_uv_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_version(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_version());
}

static mrb_value
mrb_uv_version_string(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_cstr(mrb, uv_version_string());
}

void*
mrb_uv_get_ptr(mrb_state *mrb, mrb_value v, struct mrb_data_type const *t)
{
  mrb_assert(mrb_type(v) == MRB_TT_DATA);
  if (!DATA_PTR(v)) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "already destroyed data");
  }
  return mrb_data_get_ptr(mrb, v, t);
}

void mrb_uv_error(mrb_state *mrb, int err)
{
  mrb_value argv[2];
  mrb_assert(err < 0);
  argv[0] = mrb_str_new_cstr(mrb, uv_strerror(err));
  argv[1] = mrb_symbol_value(mrb_intern_cstr(mrb, uv_err_name(err)));
  mrb_exc_raise(mrb, mrb_obj_new(mrb, E_UV_ERROR, 2, argv));
}

static mrb_value
mrb_uv_free_memory(mrb_state *mrb, mrb_value self)
{
  return mrb_float_value(mrb, (mrb_float)uv_get_free_memory());
}

static mrb_value
mrb_uv_total_memory(mrb_state *mrb, mrb_value self)
{
  return mrb_float_value(mrb, (mrb_float)uv_get_total_memory());
}

static mrb_value
mrb_uv_hrtime(mrb_state *mrb, mrb_value self)
{
  return mrb_float_value(mrb, (mrb_float)uv_hrtime());
}

static mrb_value
mrb_uv_disable_stdio_inheritance(mrb_state *mrb, mrb_value self)
{
  return uv_disable_stdio_inheritance(), self;
}

static mrb_value
mrb_uv_process_title(mrb_state *mrb, mrb_value self)
{
  char buf[PATH_MAX];
  int err;

  err = uv_get_process_title(buf, PATH_MAX);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  return mrb_str_new_cstr(mrb, buf);
}

static mrb_value
mrb_uv_process_title_set(mrb_state *mrb, mrb_value self)
{
  char *z;
  mrb_get_args(mrb, "z", &z);

  uv_set_process_title(z);
  return mrb_uv_process_title(mrb, self);
}

static mrb_value
mrb_uv_rusage(mrb_state *mrb, mrb_value self)
{
  uv_rusage_t usage;
  int err;
  mrb_value ret, tv;

  err = uv_getrusage(&usage);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }

  ret = mrb_hash_new_capa(mrb, 16);
#define set_val(name) \
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, #name)), mrb_float_value(mrb, usage.ru_ ## name))

  set_val(maxrss);
  set_val(ixrss);
  set_val(idrss);
  set_val(isrss);
  set_val(minflt);
  set_val(majflt);
  set_val(nswap);
  set_val(inblock);
  set_val(oublock);
  set_val(msgsnd);
  set_val(msgrcv);
  set_val(nsignals);
  set_val(nvcsw);
  set_val(nivcsw);

#undef set_val

  tv = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_utime.tv_sec));
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_utime.tv_usec));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "utime")), tv);

  tv = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_stime.tv_sec));
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_stime.tv_usec));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "stime")), tv);

  return ret;
}

static mrb_value
mrb_uv_cpu_info(mrb_state *mrb, mrb_value self)
{
  uv_cpu_info_t *info;
  int info_count, err, i, ai;
  mrb_value ret;

  err = uv_cpu_info(&info, &info_count);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }

  ret = mrb_ary_new_capa(mrb, info_count);
  ai = mrb_gc_arena_save(mrb);
  for (i = 0; i < info_count; ++i) {
    mrb_value c = mrb_hash_new_capa(mrb, 3), t = mrb_hash_new_capa(mrb, 5);

    mrb_hash_set(mrb, t, mrb_symbol_value(mrb_intern_lit(mrb, "user")), mrb_float_value(mrb, info[i].cpu_times.user));
    mrb_hash_set(mrb, t, mrb_symbol_value(mrb_intern_lit(mrb, "nice")), mrb_float_value(mrb, info[i].cpu_times.nice));
    mrb_hash_set(mrb, t, mrb_symbol_value(mrb_intern_lit(mrb, "sys")), mrb_float_value(mrb, info[i].cpu_times.sys));
    mrb_hash_set(mrb, t, mrb_symbol_value(mrb_intern_lit(mrb, "idle")), mrb_float_value(mrb, info[i].cpu_times.idle));
    mrb_hash_set(mrb, t, mrb_symbol_value(mrb_intern_lit(mrb, "irq")), mrb_float_value(mrb, info[i].cpu_times.irq));

    mrb_hash_set(mrb, c, mrb_symbol_value(mrb_intern_lit(mrb, "model")), mrb_str_new_cstr(mrb, info[i].model));
    mrb_hash_set(mrb, c, mrb_symbol_value(mrb_intern_lit(mrb, "speed")), mrb_fixnum_value(info[i].speed));
    mrb_hash_set(mrb, c, mrb_symbol_value(mrb_intern_lit(mrb, "cpu_times")), t);

    mrb_ary_push(mrb, ret, c);
    mrb_gc_arena_restore(mrb, ai);
  }

  uv_free_cpu_info(info, info_count);
  return ret;
}

static mrb_value
mrb_uv_interface_addresses(mrb_state *mrb, mrb_value self)
{
  uv_interface_address_t *addr;
  int addr_count, err, i, ai;
  mrb_value ret;
  struct RClass *UV = mrb_module_get(mrb, "UV");

  err = uv_interface_addresses(&addr, &addr_count);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }

  ret = mrb_ary_new_capa(mrb, addr_count);
  ai = mrb_gc_arena_save(mrb);
  for (i = 0; i < addr_count; ++i) {
    int j;
    mrb_value n = mrb_hash_new_capa(mrb, 5), phys = mrb_ary_new_capa(mrb, 6);

    for (j = 0; j < 6; ++j) {
      mrb_ary_push(mrb, phys, mrb_fixnum_value((uint8_t)addr[i].phys_addr[j]));
    }

    mrb_hash_set(mrb, n, mrb_symbol_value(mrb_intern_lit(mrb, "name")), mrb_str_new_cstr(mrb, addr[i].name));
    mrb_hash_set(mrb, n, mrb_symbol_value(mrb_intern_lit(mrb, "is_internal")), mrb_bool_value(addr[i].is_internal));
    mrb_hash_set(mrb, n, mrb_symbol_value(mrb_intern_lit(mrb, "phys_addr")), phys);
    {
      struct RClass *cls;
      void *ptr;
      struct mrb_data_type const *type;

      switch(addr[i].address.address4.sin_family) {
      case AF_INET:
        cls = mrb_class_get_under(mrb, UV, "Ip4Addr");
        ptr = mrb_malloc(mrb, sizeof(struct sockaddr_in));
        *(struct sockaddr_in*)ptr = addr[i].address.address4;
        type = &mrb_uv_ip4addr_type;
        break;
      case AF_INET6:
        cls = mrb_class_get_under(mrb, UV, "Ip6Addr");
        ptr = mrb_malloc(mrb, sizeof(struct sockaddr_in6));
        *(struct sockaddr_in6*)ptr = addr[i].address.address6;
        type = &mrb_uv_ip6addr_type;
        break;
      default: mrb_assert(FALSE);
      }
      mrb_hash_set(mrb, n, mrb_symbol_value(mrb_intern_lit(mrb, "address")),
                   mrb_obj_value(Data_Wrap_Struct(mrb, cls, type, ptr)));
    }

    {
      struct RClass *cls;
      void *ptr;
      struct mrb_data_type const *type;

      switch(addr[i].netmask.netmask4.sin_family) {
      case AF_INET:
        cls = mrb_class_get_under(mrb, UV, "Ip4Addr");
        ptr = mrb_malloc(mrb, sizeof(struct sockaddr_in));
        *(struct sockaddr_in*)ptr = addr[i].netmask.netmask4;
        type = &mrb_uv_ip4addr_type;
        break;
      case AF_INET6:
        cls = mrb_class_get_under(mrb, UV, "Ip6Addr");
        ptr = mrb_malloc(mrb, sizeof(struct sockaddr_in6));
        *(struct sockaddr_in6*)ptr = addr[i].netmask.netmask6;
        type = &mrb_uv_ip6addr_type;
        break;
      default: mrb_assert(FALSE);
      }
      mrb_hash_set(mrb, n, mrb_symbol_value(mrb_intern_lit(mrb, "netmask")),
                   mrb_obj_value(Data_Wrap_Struct(mrb, cls, type, ptr)));
    }

    mrb_ary_push(mrb, ret, n);
    mrb_gc_arena_restore(mrb, ai);
  }

  uv_free_interface_addresses(addr, addr_count);
  return ret;
}

typedef struct mrb_uv_work_t {
  mrb_state *mrb;
  mrb_value block;
  mrb_value object;
  uv_work_t *uv;
} mrb_uv_work_t;

static struct mrb_data_type const mrb_uv_work_type = {
  "uv_work", NULL
};

static void
mrb_uv_work_cb(uv_work_t *w)
{
  mrb_uv_work_t *data = (mrb_uv_work_t*)w->data;
  mrb_yield_argv(data->mrb, data->block, 0, NULL);
}

static void
mrb_uv_after_work_cb(uv_work_t *uv, int err)
{
  mrb_uv_work_t *work = (mrb_uv_work_t*)uv->data;
  mrb_free(work->mrb, work);
  mrb_free(work->mrb, uv);
  DATA_PTR(work->object) = NULL;
  if (err < 0) {
    mrb_uv_error(work->mrb, err);
  }
}

static mrb_value
mrb_uv_queue_work(mrb_state *mrb, mrb_value self)
{
  mrb_value blk;
  mrb_uv_work_t *work;
  int err;

  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expected block to UV.queue_work");
  }

  work = (mrb_uv_work_t*)mrb_malloc(mrb, sizeof(mrb_uv_work_t));
  work->mrb = mrb;
  work->block = blk;
  work->uv = (uv_work_t*)mrb_malloc(mrb, sizeof(uv_work_t));
  work->uv->data = work;
  err = uv_queue_work(uv_default_loop(), work->uv, mrb_uv_work_cb, mrb_uv_after_work_cb);
  if (err < 0) {
    mrb_free(mrb, work->uv);
    mrb_free(mrb, work);
    mrb_uv_error(mrb, err);
  }

  work->object = mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &mrb_uv_work_type, work));
  mrb_iv_set(mrb, work->object, mrb_intern_lit(mrb, "work_cb"), blk);
  mrb_uv_gc_protect(mrb, work->object);

  return self;
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
  struct RClass* _class_uv_error;
  mrb_value uv_gc_table;

  _class_uv_error = mrb_define_class(mrb, "UVError", E_NAME_ERROR);

  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_module_function(mrb, _class_uv, "run", mrb_uv_run, ARGS_NONE());
  //mrb_define_module_function(mrb, _class_uv, "once", mrb_uv_once, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "default_loop", mrb_uv_default_loop, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "ip6_addr", mrb_uv_ip6_addr, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "getaddrinfo", mrb_uv_getaddrinfo, ARGS_REQ(3));
  mrb_define_module_function(mrb, _class_uv, "gc", mrb_uv_gc, ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "guess_handle", mrb_uv_guess_handle, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv, "exepath", mrb_uv_exepath, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "cwd", mrb_uv_cwd, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "chdir", mrb_uv_chdir, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv, "loadavg", mrb_uv_loadavg, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "kill", mrb_uv_kill, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "version", mrb_uv_version, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "version_string", mrb_uv_version_string, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "free_memory", mrb_uv_free_memory, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "total_memory", mrb_uv_total_memory, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "hrtime", mrb_uv_hrtime, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "disable_stdio_inheritance", mrb_uv_disable_stdio_inheritance, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "process_title", mrb_uv_process_title, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "process_title=", mrb_uv_process_title_set, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "rusage", mrb_uv_rusage, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "cpu_info", mrb_uv_cpu_info, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "interface_addresses", mrb_uv_interface_addresses, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "queue_work", mrb_uv_queue_work, MRB_ARGS_NONE());

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
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "close", mrb_uv_loop_close, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "data=", mrb_uv_data_set, ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "data", mrb_uv_data_get, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "alive?", mrb_uv_loop_alive, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "stop", mrb_uv_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "update_time", mrb_uv_update_time, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "backend_fd", mrb_uv_backend_fd, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "backend_timeout", mrb_uv_backend_timeout, MRB_ARGS_NONE());
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

  /* TODO
  uv_poll_init
  uv_poll_init_socket
  uv_poll_start
  uv_poll_stop
  uv_check_init
  uv_check_start
  uv_check_stop
  uv_cancel
  uv_setup_args
  uv_uptime
  uv_inet_ntop
  uv_inet_pton
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

  mrb_mruby_uv_gem_init_fs(mrb, _class_uv);
  mrb_mruby_uv_gem_init_handle(mrb, _class_uv);
  mrb_mruby_uv_gem_init_thread(mrb, _class_uv);
  mrb_mruby_uv_gem_init_dl(mrb, _class_uv);

  uv_gc_table = mrb_ary_new(mrb);
  mrb_define_const(mrb, _class_uv, "$GC", uv_gc_table);
}

void
mrb_mruby_uv_gem_final(mrb_state* mrb) {
  mrb_uv_gc_table_clean(mrb);
  uv_loop_close(uv_default_loop());
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
