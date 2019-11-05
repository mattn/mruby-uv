#define _WIN32_WINNT 0x0600
#include "mruby/uv.h"
#include "mrb_uv.h"

/*********************************************************
 * main
 *********************************************************/

mrb_value
mrb_uv_from_uint64(mrb_state *mrb, uint64_t v)
{
  return MRB_INT_MAX < v? mrb_float_value(mrb, (mrb_float)v) : mrb_fixnum_value(v);
}

mrb_value
mrb_uv_gc_table_get(mrb_state *mrb)
{
  return mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "UV")), mrb_intern_lit(mrb, "$GC"));
}

void
mrb_uv_gc_table_clean(mrb_state *mrb, uv_loop_t *target)
{
  int i, new_i = 0;
  mrb_value t = mrb_uv_gc_table_get(mrb);
  mrb_value const *ary = RARRAY_PTR(t);
  for (i = 0; i < RARRAY_LEN(t); ++i) {
    mrb_value const v = ary[i];
    mrb_uv_handle *h;
    if (!DATA_PTR(v)) { continue; }
    if (DATA_TYPE(v) != &mrb_uv_handle_type) { continue; }

    h = (mrb_uv_handle*)DATA_PTR(v);
    if (target && h->handle.loop != target) { continue; }

    mrb_uv_handle_type.dfree(mrb, h);
  }
  mrb_ary_resize(mrb, t, new_i);
  uv_run(uv_default_loop(), UV_RUN_ONCE);
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
  mrb_uv_gc_table_clean(mrb, NULL);
  mrb_full_gc(mrb);
  return self;
}

static mrb_value
mrb_uv_run(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_mode = UV_RUN_DEFAULT;
  mrb_get_args(mrb, "|i", &arg_mode);
  return mrb_fixnum_value(uv_run(mrb_uv_current_loop(mrb), arg_mode));
}

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
  return self;
}

#if MRB_UV_CHECK_VERSION(1, 9, 0)

// UV::Passwd
static void
mrb_uv_passwd_free(mrb_state *mrb, void *p)
{
  uv_passwd_t *passwd = (uv_passwd_t*)p;
  if (!p) { return; }

  uv_os_free_passwd(passwd);
  mrb_free(mrb, p);
}

static mrb_data_type const passwd_type = { "uv_passwd", mrb_uv_passwd_free };

static mrb_value
mrb_uv_passwd_init(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t passwd, *ptr;

  mrb_get_args(mrb, "");

  mrb_uv_check_error(mrb, uv_os_get_passwd(&passwd));
  ptr = (uv_passwd_t*)mrb_malloc(mrb, sizeof(uv_passwd_t));
  *ptr = passwd;
  DATA_PTR(self) = ptr;
  DATA_TYPE(self) = &passwd_type;

  return self;
}

static mrb_value
mrb_uv_passwd_username(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t *p;
  Data_Get_Struct(mrb, self, &passwd_type, p);
  return mrb_str_new_cstr(mrb, p->username);
}

static mrb_value
mrb_uv_passwd_shell(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t *p;
  Data_Get_Struct(mrb, self, &passwd_type, p);
  return p->shell? mrb_str_new_cstr(mrb, p->shell) : mrb_nil_value();
}

static mrb_value
mrb_uv_passwd_homedir(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t *p;
  Data_Get_Struct(mrb, self, &passwd_type, p);
  return mrb_str_new_cstr(mrb, p->homedir);
}

static mrb_value
mrb_uv_passwd_uid(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t *p;
  Data_Get_Struct(mrb, self, &passwd_type, p);
  return mrb_fixnum_value(p->uid);
}

static mrb_value
mrb_uv_passwd_gid(mrb_state *mrb, mrb_value self)
{
  uv_passwd_t *p;
  Data_Get_Struct(mrb, self, &passwd_type, p);
  return mrb_fixnum_value(p->gid);
}

#endif

/*
 * UV::Req
 */
static void
mrb_uv_req_free(mrb_state *mrb, void *p)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)p;

  if (!p) { return; }

  if (req->req.req.type == UV_FS) {
    uv_fs_req_cleanup((uv_fs_t*)&req->req);
  }
  mrb_free(mrb, p);
}

static mrb_data_type const req_type = { "uv_req", mrb_uv_req_free };

static mrb_uv_req_t*
mrb_uv_req_alloc(mrb_state *mrb)
{
  mrb_uv_req_t *p;
  struct RClass *cls;
  mrb_value ret;
  int ai;

  ai = mrb_gc_arena_save(mrb);
  cls = mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "Req");
  p = (mrb_uv_req_t*)mrb_malloc(mrb, sizeof(mrb_uv_req_t));
  ret = mrb_obj_value(mrb_data_object_alloc(mrb, cls, p, &req_type));
  p->mrb = mrb;
  p->instance = ret;
  p->req.req.data = p;
  p->is_used = FALSE;

  mrb_uv_gc_protect(mrb, ret);
  mrb_gc_arena_restore(mrb, ai);
  return p;
}

mrb_uv_req_t*
mrb_uv_req_current(mrb_state *mrb, mrb_value blk, mrb_value *result)
{
  mrb_value cur_loop = mrb_uv_current_loop_obj(mrb);
  mrb_value cur_yarn = mrb_funcall(mrb, cur_loop, "current_yarn", 0);
  mrb_sym const sym = mrb_intern_lit(mrb, "_req");
  mrb_uv_req_t *ret;

  mrb_assert(!mrb_nil_p(cur_loop));

  if (!mrb_nil_p(blk)) { // block passed
    ret = mrb_uv_req_alloc(mrb);
    *result = ret->instance;
  } else {
    mrb_value req, target;
    target = mrb_nil_p(cur_yarn)? cur_loop : cur_yarn;
    req = mrb_iv_get(mrb, target, sym);

    if (mrb_nil_p(req)) {
      ret = mrb_uv_req_alloc(mrb);
      mrb_iv_set(mrb, target, sym, ret->instance);
    } else {
      ret = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, req, &req_type);
    }
    req = ret->instance;

    if (mrb_nil_p(cur_yarn)) {
      *result = ret->instance;
    } else {
      *result = mrb_fiber_yield(mrb, 1, &req);
      blk = mrb_funcall(mrb, cur_yarn, "to_proc", 0);
    }
  }

  mrb_assert(!ret->is_used);

  ret->is_used = TRUE;
  mrb_iv_set(mrb, ret->instance, mrb_intern_lit(mrb, "uv_cb"), blk);
  ret->block = blk;

  return ret;
}

void
mrb_uv_req_check_error(mrb_state *mrb, mrb_uv_req_t *req, int err)
{
  if (mrb_nil_p(req->block) || err < 0) {
    mrb_uv_req_clear(req);
  }

  mrb_uv_check_error(mrb, err);
}

void
mrb_uv_req_clear(mrb_uv_req_t *req)
{
  mrb_state *mrb = req->mrb;

  mrb_assert(req->is_used);

  if (req->req.req.type == UV_FS) {
    uv_fs_req_cleanup(&req->req.fs);
    req->req.fs.result = 0;
  }
  req->req.req.type = UV_UNKNOWN_REQ;
  req->is_used = FALSE;
  req->block = mrb_nil_value();
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "uv_cb"), mrb_nil_value());
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "buf"), mrb_nil_value());
}

void
mrb_uv_req_yield(mrb_uv_req_t *req, mrb_int argc, mrb_value const *argv)
{
  mrb_value const b = req->block;
  mrb_gc_protect(req->mrb, b);
  mrb_uv_req_clear(req);
  mrb_yield_argv(req->mrb, b, argc, argv);
}

void
mrb_uv_req_set_buf(mrb_uv_req_t *req, uv_buf_t *buf, mrb_value str)
{
  mrb_state *mrb = req->mrb;
  mrb_str_modify(mrb, mrb_str_ptr(str));
  *buf = uv_buf_init(RSTRING_PTR(str), RSTRING_LEN(str));
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "buf"), str);
}

static mrb_value
mrb_uv_cancel(mrb_state *mrb, mrb_value self)
{
  mrb_uv_check_error(mrb, uv_cancel(&((mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type))->req.req));
  return self;
}

static mrb_value
mrb_uv_req_type(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req;

  req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
  return mrb_fixnum_value(req->req.req.type);
  switch(req->req.req.type) {
#define XX(u, l) case UV_ ## u: return symbol_value_lit(mrb, #l);
      UV_REQ_TYPE_MAP(XX)
#undef XX

  case UV_UNKNOWN_REQ: return symbol_value_lit(mrb, "unknown");

  default:
    mrb_raisef(mrb, E_TYPE_ERROR, "Invalid uv_req_t type: %S", mrb_fixnum_value(req->req.req.type));
    return self;
  }
}

static mrb_value
mrb_uv_req_type_name(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req;

  req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
#if MRB_UV_CHECK_VERSION(1, 19, 0)
  return mrb_symbol_value(mrb_intern_cstr(mrb, uv_req_type_name(uv_req_get_type(&req->req.req))));
#else
  switch(req->req.req.type) {
#define XX(u, l) case UV_ ## u: return symbol_value_lit(mrb, #l);
      UV_REQ_TYPE_MAP(XX)
#undef XX

    case UV_UNKNOWN_REQ: return symbol_value_lit(mrb, "unknown");

    default:
      mrb_raisef(mrb, E_TYPE_ERROR, "Invalid uv_req_t type: %S", mrb_fixnum_value(req->req.req.type));
      return self;
  }
#endif
}

#if MRB_UV_CHECK_VERSION(1, 19, 0)

static mrb_value
mrb_uv_fs_req_result(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
  if (req->req.req.type != UV_FS) { mrb_raise(mrb, E_TYPE_ERROR, "not fs request"); }
  return mrb_fixnum_value(uv_fs_get_result(&req->req.fs));
}

static mrb_value
mrb_uv_fs_req_statbuf(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
  if (req->req.req.type != UV_FS) { mrb_raise(mrb, E_TYPE_ERROR, "not fs request"); }
  return mrb_uv_create_stat(mrb, uv_fs_get_statbuf(&req->req.fs));
}

static mrb_value
mrb_uv_fs_req_path(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
  if (req->req.req.type != UV_FS) { mrb_raise(mrb, E_TYPE_ERROR, "not fs request"); }
  return mrb_str_new_cstr(mrb, uv_fs_get_path(&req->req.fs));
}

static mrb_value
mrb_uv_fs_req_type(mrb_state *mrb, mrb_value self)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)mrb_uv_get_ptr(mrb, self, &req_type);
  if (req->req.req.type != UV_FS) { mrb_raise(mrb, E_TYPE_ERROR, "not fs request"); }
  return mrb_fixnum_value(uv_fs_get_type(&req->req.fs));
}

#endif

/*********************************************************
 * UV::Loop
 *********************************************************/
static void
mrb_uv_loop_free(mrb_state *mrb, void *p)
{
  uv_loop_t *l = (uv_loop_t*)p;

  if (!l || l == uv_default_loop()) { return; }

  // mrb_uv_gc_table_clean(mrb, l);
  uv_walk(l, mrb_uv_close_handle_belongs_to_vm, mrb);
  uv_run(l, UV_RUN_ONCE);
  mrb_uv_check_error(mrb, uv_loop_close(l));
  mrb_free(mrb, p);
}

const struct mrb_data_type mrb_uv_loop_type = {
  "uv_loop", mrb_uv_loop_free
};

static mrb_value
mrb_uv_default_loop(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(
      mrb, mrb_const_get(
          mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "UV")),
      mrb_intern_lit(mrb, "default_loop"));
}

static mrb_value
mrb_uv_current_loop_meth(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_current_loop_obj(mrb);
}

static mrb_value
mrb_uv_loop_init(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *l = (uv_loop_t*)mrb_malloc(mrb, sizeof(uv_loop_t));
  mrb_uv_check_error(mrb, uv_loop_init(l));
  DATA_PTR(self) = l;
  DATA_TYPE(self) = &mrb_uv_loop_type;
  return self;
}

static mrb_value
mrb_uv_loop_run(mrb_state *mrb, mrb_value self)
{
  uv_loop_t* loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  mrb_int arg_mode = UV_RUN_DEFAULT;

  mrb_get_args(mrb, "|i", &arg_mode);
  mrb_uv_check_error(mrb, uv_run(loop, arg_mode));
  return self;
}

static mrb_value
mrb_uv_loop_close(mrb_state *mrb, mrb_value self)
{
  uv_loop_t* loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);

  if (loop == uv_default_loop()) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot close default uv loop");
  }

  mrb_uv_gc_table_clean(mrb, loop);
  uv_walk(loop, mrb_uv_close_handle_belongs_to_vm, mrb);
  uv_run(loop, UV_RUN_ONCE);
  mrb_uv_check_error(mrb, uv_loop_close(loop));
  DATA_PTR(self) = NULL;
  DATA_TYPE(self) = NULL;
  mrb_free(mrb, loop);

  return self;
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
mrb_uv_now(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop;

  loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  return mrb_uv_from_uint64(mrb, uv_now(loop));
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

#if MRB_UV_CHECK_VERSION(1, 0, 2)

static mrb_value
mrb_uv_loop_configure(mrb_state *mrb, mrb_value self) {
  mrb_value h, block_signal;
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);

  mrb_get_args(mrb, "H", &h);

  if (!mrb_nil_p(block_signal = mrb_hash_get(mrb, h, mrb_symbol_value(mrb_intern_lit(mrb, "block_signal"))))) {
    mrb_uv_check_error(mrb, uv_loop_configure(loop, UV_LOOP_BLOCK_SIGNAL, mrb_fixnum(block_signal)));
  }

  return self;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 12, 0)

static mrb_value
mrb_uv_loop_fork(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  mrb_uv_check_error(mrb, uv_loop_fork(loop));
  return self;
}

#endif

static mrb_value
mrb_uv_loop_eq(mrb_state *mrb, mrb_value self)
{
  uv_loop_t *loop = (uv_loop_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_loop_type);
  uv_loop_t *other;

  mrb_get_args(mrb, "d", &other, &mrb_uv_loop_type);

  return mrb_bool_value(loop == other);
}

static mrb_value
mrb_uv_loop_make_current(mrb_state *mrb, mrb_value self)
{
  mrb_iv_set(
      mrb, mrb_const_get(
          mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "UV")),
      mrb_intern_lit(mrb, "current_loop"), self);
  return self;
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
  mrb_uv_args_int argc;
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
    mrb_uv_check_error(mrb, uv_ip4_addr(mrb_str_to_cstr(mrb, arg_host), mrb_fixnum(arg_port), &vaddr));
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
  struct sockaddr_in* addr = NULL;
  char name[256];

  Data_Get_Struct(mrb, self, &mrb_uv_ip4addr_type, addr);
  if (!addr) {
    return mrb_nil_value();
  }
  mrb_uv_check_error(mrb, uv_ip4_name(addr, name, sizeof(name)));
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
  mrb_uv_args_int argc;
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
    mrb_uv_check_error(mrb, uv_ip6_addr(mrb_str_to_cstr(mrb, arg_host), mrb_fixnum(arg_port), &vaddr));
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
  struct sockaddr_in6* addr = NULL;
  char name[256];

  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
  if (!addr) {
    return mrb_nil_value();
  }
  mrb_uv_check_error(mrb, uv_ip6_name(addr, name, sizeof(name)));
  return mrb_str_new(mrb, name, strlen(name));
}

static mrb_value
mrb_uv_ip6addr_sin_port(mrb_state *mrb, mrb_value self)
{
  struct sockaddr_in6* addr = NULL;
  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
  return mrb_fixnum_value(htons(addr->sin6_port));
}

static mrb_value
mrb_uv_ip6addr_sin6_scope_id(mrb_state *mrb, mrb_value self)
{
  struct sockaddr_in6* addr = NULL;
  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
  return mrb_fixnum_value(addr->sin6_scope_id);
}

#if MRB_UV_CHECK_VERSION(1, 16, 0)

static mrb_value
mrb_uv_ip6addr_if_indextoiid(mrb_state *mrb, mrb_value self)
{
  struct sockaddr_in6* addr = NULL;
  char ifname[UV_IF_NAMESIZE];
  size_t ifname_size = sizeof(ifname);
  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
  mrb_uv_check_error(mrb, uv_if_indextoiid(addr->sin6_scope_id, ifname, &ifname_size));
  return mrb_str_new(mrb, ifname, ifname_size);
}

static mrb_value
mrb_uv_ip6addr_if_indextoname(mrb_state *mrb, mrb_value self)
{
  struct sockaddr_in6* addr = NULL;
  char ifname[UV_IF_NAMESIZE];
  size_t ifname_size = sizeof(ifname);
  Data_Get_Struct(mrb, self, &mrb_uv_ip6addr_type, addr);
  mrb_uv_check_error(mrb, uv_if_indextoname(addr->sin6_scope_id, ifname, &ifname_size));
  return mrb_str_new(mrb, ifname, ifname_size);
}

static mrb_value
mrb_uv_if_indextoiid(mrb_state *mrb, mrb_value self)
{
  char ifname[UV_IF_NAMESIZE];
  size_t ifname_size = sizeof(ifname);
  mrb_int idx;
  mrb_get_args(mrb, "i", &idx);
  mrb_uv_check_error(mrb, uv_if_indextoiid(idx, ifname, &ifname_size));
  return mrb_str_new(mrb, ifname, ifname_size);
}

static mrb_value
mrb_uv_if_indextoname(mrb_state *mrb, mrb_value self)
{
  char ifname[UV_IF_NAMESIZE];
  size_t ifname_size = sizeof(ifname);
  mrb_int idx;
  mrb_get_args(mrb, "i", &idx);
  mrb_uv_check_error(mrb, uv_if_indextoname(idx, ifname, &ifname_size));
  return mrb_str_new(mrb, ifname, ifname_size);
}

#endif

/*
 * UV.getnameinfo
 */
static void
mrb_uv_getnameinfo_cb(uv_getnameinfo_t *uv_req, int status, char const *host, char const* service)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)uv_req->data;
  mrb_state *mrb = req->mrb;
  mrb_value args[] = {
    mrb_str_new_cstr(mrb, host),
    mrb_str_new_cstr(mrb, service),
    mrb_uv_create_status(mrb, status),
  };
  mrb_uv_req_yield(req, 3, args);
}

static mrb_value
mrb_uv_getnameinfo(mrb_state *mrb, mrb_value self)
{
  mrb_value block, sock, ret;
  mrb_int flags = 0;
  struct sockaddr* addr;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&o|i", &block, &sock, &flags);

  addr = (struct sockaddr*)mrb_data_check_get_ptr(mrb, sock, &mrb_uv_ip4addr_type);
  if (!addr) {
    addr = (struct sockaddr*)mrb_data_check_get_ptr(mrb, sock, &mrb_uv_ip6addr_type);
  }

  req = mrb_uv_req_current(mrb, block, &ret);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Expected callback in uv_getaddrinfo.");
  }
  mrb_uv_req_check_error(mrb, req, uv_getnameinfo(
      mrb_uv_current_loop(mrb), &req->req.getnameinfo,
      mrb_uv_getnameinfo_cb, addr, flags));
  return ret;
}

/*********************************************************
 * UV::Addrinfo
 *********************************************************/
static void
uv_addrinfo_free(mrb_state *mrb, void *p)
{
  uv_freeaddrinfo((struct addrinfo*)p);
}

static void
uv_addrinfo_nofree(mrb_state *mrb, void *p) {}

static const struct mrb_data_type uv_addrinfo_type = {
  "uv_addrinfo", uv_addrinfo_free,
};

static const struct mrb_data_type uv_addrinfo_nofree_type = {
  "uv_addrinfo", uv_addrinfo_nofree,
};

static struct addrinfo const *
addrinfo_ptr(mrb_state *mrb, mrb_value v)
{
  void *ret = mrb_data_check_get_ptr(mrb, v, &uv_addrinfo_type);
  if (ret) { return (struct addrinfo*)ret; }
  return (struct addrinfo*)mrb_data_get_ptr(mrb, v, &uv_addrinfo_nofree_type);
}

static void
_uv_getaddrinfo_cb(uv_getaddrinfo_t* uv_req, int status, struct addrinfo* res)
{
  mrb_value args[2];
  mrb_uv_req_t* req = (mrb_uv_req_t*) uv_req->data;
  mrb_state* mrb = req->mrb;

  mrb_value c = mrb_nil_value();
  if (status == 0) {
    struct RClass* _class_uv = mrb_module_get(mrb, "UV");
    struct RClass* _class_uv_addrinfo = mrb_class_get_under(mrb, _class_uv, "Addrinfo");
    c = mrb_obj_new(mrb, _class_uv_addrinfo, 0, NULL);
    DATA_PTR(c) = res;
    DATA_TYPE(c) = &uv_addrinfo_type;
  }

  args[0] = mrb_uv_create_status(mrb, status);
  args[1] = c;
  mrb_uv_req_yield(req, 2, args);
}

static mrb_value
mrb_uv_getaddrinfo(mrb_state *mrb, mrb_value self)
{
  mrb_value node, service, b = mrb_nil_value(), ret;
  mrb_value mrb_hints = mrb_hash_new(mrb);
  mrb_uv_req_t* req;
  mrb_value value;
  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_flags = 0;

  mrb_get_args(mrb, "SS|H&", &node, &service, &mrb_hints, &b);

  // parse hints
  value = mrb_hash_get(mrb, mrb_hints, mrb_symbol_value(mrb_intern_lit(mrb, "ai_family")));
  if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "ipv4")))) {
    hints.ai_family = AF_INET;
  } else if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "ipv6")))) {
    hints.ai_family = AF_INET6;
  }
  value = mrb_hash_get(mrb, mrb_hints, mrb_symbol_value(mrb_intern_lit(mrb, "datagram")));
  if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "dgram")))) {
    hints.ai_socktype = SOCK_DGRAM;
  } else if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "stream")))) {
    hints.ai_socktype = SOCK_STREAM;
  }
  value = mrb_hash_get(mrb, mrb_hints, mrb_symbol_value(mrb_intern_lit(mrb, "protocol")));
  if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "ip")))) {
    hints.ai_protocol = IPPROTO_IP;
  } else if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "udp")))) {
    hints.ai_protocol = IPPROTO_UDP;
  } else if (mrb_obj_equal(mrb, value, mrb_symbol_value(mrb_intern_lit(mrb, "tcp")))) {
    hints.ai_protocol = IPPROTO_TCP;
  }
  value = mrb_hash_get(mrb, mrb_hints, mrb_symbol_value(mrb_intern_lit(mrb, "flags")));
  if (mrb_obj_is_kind_of(mrb, value, mrb->fixnum_class)) {
    hints.ai_flags = mrb_int(mrb, value);
  }

  req = mrb_uv_req_current(mrb, b, &ret);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Expected callback in uv_getaddrinfo.");
  }
  mrb_uv_req_check_error(mrb, req, uv_getaddrinfo(
      mrb_uv_current_loop(mrb), &req->req.getaddrinfo, _uv_getaddrinfo_cb,
      RSTRING_PTR(node), RSTRING_PTR(service), &hints));
  return ret;
}

static mrb_value
mrb_uv_addrinfo_flags(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(addrinfo_ptr(mrb, self)->ai_flags);
}

static mrb_value
mrb_uv_addrinfo_family(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(addrinfo_ptr(mrb, self)->ai_family);
}

static mrb_value
mrb_uv_addrinfo_socktype(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(addrinfo_ptr(mrb, self)->ai_socktype);
}

static mrb_value
mrb_uv_addrinfo_protocol(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(addrinfo_ptr(mrb, self)->ai_protocol);
}

static mrb_value
mrb_uv_addrinfo_addr(mrb_state *mrb, mrb_value self)
{
  struct addrinfo const* addr = addrinfo_ptr(mrb, self);
  struct RClass* _class_uv = mrb_module_get(mrb, "UV");
  mrb_value c = mrb_nil_value();
  mrb_value args[1];

  switch (addr->ai_family) {
  case AF_INET:
    {
      struct RClass* _class_uv_ip4addr = mrb_class_get_under(mrb, _class_uv, "Ip4Addr");
      struct sockaddr_in* saddr = (struct sockaddr_in*)mrb_malloc(mrb, sizeof(struct sockaddr_in));
      *saddr = *(struct sockaddr_in*)addr->ai_addr;
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
      *saddr = *(struct sockaddr_in6*)addr->ai_addr;
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
  struct addrinfo const* addr = addrinfo_ptr(mrb, self);
  return mrb_str_new_cstr(mrb,
    addr->ai_canonname ? addr->ai_canonname : "");
}

static mrb_value
mrb_uv_addrinfo_next(mrb_state *mrb, mrb_value self)
{
  struct addrinfo const* addr = addrinfo_ptr(mrb, self);
  struct RClass* _class_uv, *_class_uv_addrinfo;
  mrb_value c;

  if (!addr->ai_next) { return mrb_nil_value(); }

  _class_uv = mrb_module_get(mrb, "UV");
  _class_uv_addrinfo = mrb_class_get_under(mrb, _class_uv, "Addrinfo");

  c = mrb_obj_new(mrb, _class_uv_addrinfo, 0, NULL);
  mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "parent_addrinfo"), self);
  DATA_PTR(c) = addr->ai_next;
  DATA_TYPE(c) = &uv_addrinfo_nofree_type;
  return c;
}

static mrb_value
mrb_uv_guess_handle(mrb_state *mrb, mrb_value self)
{
  mrb_int fd;
  uv_handle_type h;
  mrb_get_args(mrb, "i", &fd);

  h = uv_guess_handle(fd);

  switch(h) {
  case UV_FILE: return symbol_value_lit(mrb, "file");

#define XX(t, l) case UV_ ## t: return symbol_value_lit(mrb, #l);
  UV_HANDLE_TYPE_MAP(XX)
#undef XX

  default:
  case UV_UNKNOWN_HANDLE:
    return symbol_value_lit(mrb, "unknown");
  }
}

static mrb_value
mrb_uv_exepath(mrb_state *mrb, mrb_value self)
{
  char buf[PATH_MAX];
  size_t s = sizeof(buf);
  mrb_uv_check_error(mrb, uv_exepath(buf, &s));
  return mrb_str_new(mrb, buf, s);
}

static mrb_value
mrb_uv_cwd(mrb_state *mrb, mrb_value self)
{
  char buf[PATH_MAX];
  size_t s = sizeof(buf);
  mrb_uv_check_error(mrb, uv_cwd(buf, &s));
  return mrb_str_new(mrb, buf, s);
}

static mrb_value
mrb_uv_chdir(mrb_state *mrb, mrb_value self)
{
  char *z;
  mrb_get_args(mrb, "z", &z);
  mrb_uv_check_error(mrb, uv_chdir(z));
  return self;
}

static mrb_value
mrb_uv_kill(mrb_state *mrb, mrb_value self)
{
  mrb_int pid, sig;
  mrb_get_args(mrb, "ii", &pid, &sig);
  mrb_uv_check_error(mrb, uv_kill(pid, sig));
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
  if (mrb_type(v) == MRB_TT_DATA && !DATA_PTR(v)) {
    mrb_raise(mrb, E_UV_ERROR, "uninitialized or already destroyed data");
  }
  return mrb_data_get_ptr(mrb, v, t);
}

mrb_value
mrb_uv_create_error(mrb_state *mrb, int err)
{
  mrb_value argv[] = {
    mrb_str_new_cstr(mrb, uv_strerror(err)),
    mrb_symbol_value(mrb_intern_cstr(mrb, uv_err_name(err))),
  };
  mrb_assert(err < 0);
  return mrb_obj_new(mrb, E_UV_ERROR, 2, argv);
}

mrb_value
mrb_uv_create_status(mrb_state *mrb, int st)
{
  if (st < 0) { return mrb_uv_create_error(mrb, st); }

  mrb_assert(st == 0);
  return mrb_nil_value();
}

void
mrb_uv_check_error(mrb_state *mrb, int err)
{
  if (err >= 0) { return; }

  mrb_exc_raise(mrb, mrb_uv_create_error(mrb, err));
}

static mrb_value
mrb_uv_get_error(mrb_state *mrb, mrb_value self)
{
  mrb_int err;
  mrb_value argv[2];

  mrb_get_args(mrb, "i", &err);

  if (err >= 0) {
    return mrb_nil_value();
  }

  argv[0] = mrb_str_new_cstr(mrb, uv_strerror(err));
  argv[1] = mrb_symbol_value(mrb_intern_cstr(mrb, uv_err_name(err)));
  return mrb_obj_new(mrb, E_UV_ERROR, 2, argv);
}

#if MRB_UV_CHECK_VERSION(1, 10, 0)

static mrb_value
mrb_uv_translate_sys_error(mrb_state *mrb, mrb_value self)
{
  mrb_int err;
  mrb_get_args(mrb, "i", &err);
  return mrb_fixnum_value(uv_translate_sys_error(err));
}

#endif

static mrb_value
mrb_uv_free_memory(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_from_uint64(mrb, uv_get_free_memory());
}

static mrb_value
mrb_uv_total_memory(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_from_uint64(mrb, uv_get_total_memory());
}

static mrb_value
mrb_uv_hrtime(mrb_state *mrb, mrb_value self)
{
  return mrb_uv_from_uint64(mrb, uv_hrtime());
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

  mrb_uv_check_error(mrb, uv_get_process_title(buf, PATH_MAX));
  return mrb_str_new_cstr(mrb, buf);
}

static mrb_value
mrb_uv_process_title_set(mrb_state *mrb, mrb_value self)
{
  char const *z;
  mrb_get_args(mrb, "z", &z);

  mrb_uv_check_error(mrb, uv_set_process_title(z));
  return mrb_uv_process_title(mrb, self);
}

static mrb_value
mrb_uv_rusage(mrb_state *mrb, mrb_value self)
{
  uv_rusage_t usage;
  mrb_value ret, tv;

  mrb_uv_check_error(mrb, uv_getrusage(&usage));

  ret = mrb_hash_new_capa(mrb, 16);
#define set_val(name) \
  mrb_hash_set(mrb, ret, symbol_value_lit(mrb, #name), mrb_uv_from_uint64(mrb, usage.ru_ ## name))

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
  mrb_hash_set(mrb, ret, symbol_value_lit(mrb, "utime"), tv);

  tv = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_stime.tv_sec));
  mrb_ary_push(mrb, tv, mrb_fixnum_value(usage.ru_stime.tv_usec));
  mrb_hash_set(mrb, ret, symbol_value_lit(mrb, "stime"), tv);

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
    mrb_uv_check_error(mrb, err);
  }

  ret = mrb_ary_new_capa(mrb, info_count);
  ai = mrb_gc_arena_save(mrb);
  for (i = 0; i < info_count; ++i) {
    mrb_value c = mrb_hash_new_capa(mrb, 3), t = mrb_hash_new_capa(mrb, 5);

    mrb_hash_set(mrb, t, symbol_value_lit(mrb, "user"), mrb_uv_from_uint64(mrb, info[i].cpu_times.user));
    mrb_hash_set(mrb, t, symbol_value_lit(mrb, "nice"), mrb_uv_from_uint64(mrb, info[i].cpu_times.nice));
    mrb_hash_set(mrb, t, symbol_value_lit(mrb, "sys"), mrb_uv_from_uint64(mrb, info[i].cpu_times.sys));
    mrb_hash_set(mrb, t, symbol_value_lit(mrb, "idle"), mrb_uv_from_uint64(mrb, info[i].cpu_times.idle));
    mrb_hash_set(mrb, t, symbol_value_lit(mrb, "irq"), mrb_uv_from_uint64(mrb, info[i].cpu_times.irq));

    mrb_hash_set(mrb, c, symbol_value_lit(mrb, "model"), mrb_str_new_cstr(mrb, info[i].model));
    mrb_hash_set(mrb, c, symbol_value_lit(mrb, "speed"), mrb_fixnum_value(info[i].speed));
    mrb_hash_set(mrb, c, symbol_value_lit(mrb, "cpu_times"), t);

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
    mrb_uv_check_error(mrb, err);
  }

  ret = mrb_ary_new_capa(mrb, addr_count);
  ai = mrb_gc_arena_save(mrb);
  for (i = 0; i < addr_count; ++i) {
    int j;
    mrb_value n = mrb_hash_new_capa(mrb, 5), phys = mrb_ary_new_capa(mrb, 6);

    for (j = 0; j < 6; ++j) {
      mrb_ary_push(mrb, phys, mrb_fixnum_value((uint8_t)addr[i].phys_addr[j]));
    }

    mrb_hash_set(mrb, n, symbol_value_lit(mrb, "name"), mrb_str_new_cstr(mrb, addr[i].name));
    mrb_hash_set(mrb, n, symbol_value_lit(mrb, "is_internal"), mrb_bool_value(addr[i].is_internal));
    mrb_hash_set(mrb, n, symbol_value_lit(mrb, "phys_addr"), phys);
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
      mrb_hash_set(mrb, n, symbol_value_lit(mrb, "address"), mrb_obj_value(Data_Wrap_Struct(mrb, cls, type, ptr)));
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
      mrb_hash_set(mrb, n, symbol_value_lit(mrb, "netmask"), mrb_obj_value(Data_Wrap_Struct(mrb, cls, type, ptr)));
    }

    mrb_ary_push(mrb, ret, n);
    mrb_gc_arena_restore(mrb, ai);
  }

  uv_free_interface_addresses(addr, addr_count);
  return ret;
}

static void
mrb_uv_work_cb(uv_work_t *uv_req)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)uv_req->data;
  mrb_value cfunc = req->block;

  mrb_assert(mrb_type(cfunc) == MRB_TT_PROC);
  mrb_assert(MRB_PROC_CFUNC_P(mrb_proc_ptr(cfunc)));

  mrb_proc_ptr(cfunc)->body.func(NULL, mrb_nil_value());
}

static void
mrb_uv_after_work_cb(uv_work_t *uv_req, int err)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)uv_req->data;
  mrb_state *mrb = req->mrb;
  mrb_value arg = mrb_fixnum_value(err);

  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "cfunc_cb"), mrb_nil_value());
  req->block = mrb_iv_get(mrb, req->instance, mrb_intern_lit(mrb, "uv_cb"));
  mrb_uv_req_yield(req, 1, &arg);
}

static mrb_value
mrb_uv_queue_work(mrb_state *mrb, mrb_value self)
{
  mrb_value cfunc, blk, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "o&", &cfunc, &blk);
  if (mrb_type(cfunc) != MRB_TT_PROC || !MRB_PROC_CFUNC_P(mrb_proc_ptr(cfunc))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid cfunc callback");
  }
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expected block to UV.queue_work");
  }

  req = mrb_uv_req_current(mrb, blk, &ret);
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "cfunc_cb"), cfunc);
  req->block = cfunc;
  mrb_uv_req_check_error(mrb, req, uv_queue_work(
      mrb_uv_current_loop(mrb), &req->req.work, mrb_uv_work_cb, mrb_uv_after_work_cb));
  return ret;
}

static mrb_value
mrb_uv_resident_set_memory(mrb_state *mrb, mrb_value self)
{
  size_t rss;
  mrb_uv_check_error(mrb, uv_resident_set_memory(&rss));
  return mrb_uv_from_uint64(mrb, rss);
}

static mrb_value
mrb_uv_uptime(mrb_state *mrb, mrb_value self)
{
  double t;
  mrb_uv_check_error(mrb, uv_uptime(&t));
  return mrb_float_value(mrb, (mrb_float)t);
}

uv_os_sock_t
mrb_uv_to_socket(mrb_state *mrb, mrb_value v)
{
  if (mrb_fixnum_p(v)) { /* treat raw integer as socket */
    return mrb_fixnum(v);
  }

  mrb_raisef(mrb, E_ARGUMENT_ERROR, "Cannot get socket from: %S", v);
  return 0; /* for compiler warning */
}

char**
mrb_uv_setup_args(mrb_state *mrb, int *argc, char **argv, mrb_bool set_global)
{
  int new_argc; char **new_argv;

  new_argv = uv_setup_args(*argc, argv);
  if (new_argv == argv) { // no change
    new_argc = *argc;
  } else {
    char **it = new_argv;
    new_argc = 0;
    while (*it) {
        ++new_argc;
        ++it;
    }
  }

  if (set_global) {
    int i, ai;
    mrb_value argv_val;

    mrb_gv_set(mrb, mrb_intern_lit(mrb, "$0"), mrb_str_new_cstr(mrb, new_argv[0]));

    argv_val = mrb_ary_new_capa(mrb, new_argc - 1);
    ai = mrb_gc_arena_save(mrb);
    for (i = 1; i < new_argc; ++i) {
      mrb_ary_push(mrb, argv_val, mrb_str_new_cstr(mrb, new_argv[i]));
      mrb_gc_arena_restore(mrb, ai);
    }
    mrb_define_global_const(mrb, "ARGV", argv_val);
  }

  *argc = new_argc;
  return new_argv;
}

#if MRB_UV_CHECK_VERSION(1, 12, 0)

// OS
static mrb_value
mrb_uv_get_osfhandle(mrb_state *mrb, mrb_value self)
{
  mrb_int i;
  mrb_get_args(mrb, "i", &i);
  return mrb_cptr_value(mrb, (void*)(uintptr_t)uv_get_osfhandle(i));
}

#endif

#if MRB_UV_CHECK_VERSION(1, 6, 0)

static mrb_value
mrb_uv_os_homedir(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  mrb_str_resize(mrb, buf, BUF_SIZE);

  res = uv_os_homedir(RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_os_homedir(RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 9, 0)

static mrb_value
mrb_uv_os_tmpdir(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  mrb_str_resize(mrb, buf, BUF_SIZE);

  res = uv_os_tmpdir(RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_os_tmpdir(RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 12, 0)

static mrb_value
mrb_uv_os_getenv(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  char const *env;
  mrb_get_args(mrb, "z", &env);

  mrb_str_resize(mrb, buf, BUF_SIZE);

  res = uv_os_getenv(env, RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_os_getenv(env, RSTRING_PTR(buf), &s);
  }

  if (res == UV_ENOENT) { return mrb_nil_value(); }

  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

static mrb_value
mrb_uv_os_setenv(mrb_state *mrb, mrb_value self)
{
  char *env, *val;
  mrb_get_args(mrb, "zz", &env, &val);
  mrb_uv_check_error(mrb, uv_os_setenv(env, val));
  return self;
}

static mrb_value
mrb_uv_os_unsetenv(mrb_state *mrb, mrb_value self)
{
  char *env;
  mrb_get_args(mrb, "z", &env);
  mrb_uv_check_error(mrb, uv_os_unsetenv(env));
  return self;
}

static mrb_value
mrb_uv_os_gethostname(mrb_state *mrb, mrb_value self)
{
  enum { BUF_SIZE = 128 };
  mrb_value buf = mrb_str_buf_new(mrb, BUF_SIZE);
  int res;
  size_t s = BUF_SIZE;
  mrb_str_resize(mrb, buf, BUF_SIZE);

  res = uv_os_gethostname(RSTRING_PTR(buf), &s);
  if (res == UV_ENOBUFS) {
    mrb_str_resize(mrb, buf, s);
    res = uv_os_gethostname(RSTRING_PTR(buf), &s);
  }
  mrb_uv_check_error(mrb, res);

  mrb_str_resize(mrb, buf, s);
  return buf;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 18, 0)

static mrb_value
mrb_uv_os_getpid(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_os_getpid());
}

#endif

#if MRB_UV_CHECK_VERSION(1, 16, 0)

static mrb_value
mrb_uv_os_getppid(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(uv_os_getppid());
}

#endif

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
  struct RClass* _class_uv_req;
  struct RClass* _class_uv_os;
#if MRB_UV_CHECK_VERSION(1, 9, 0)
  struct RClass* _class_uv_passwd;
#endif
  mrb_value def_loop;

  mrb_define_class(mrb, "UVError", E_NAME_ERROR);

  _class_uv = mrb_define_module(mrb, "UV");
  mrb_define_module_function(mrb, _class_uv, "run", mrb_uv_run, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "default_loop", mrb_uv_default_loop, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "current_loop", mrb_uv_current_loop_meth, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "ip4_addr", mrb_uv_ip4_addr, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "ip6_addr", mrb_uv_ip6_addr, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "getaddrinfo", mrb_uv_getaddrinfo, MRB_ARGS_REQ(3));
  mrb_define_module_function(mrb, _class_uv, "getnameinfo", mrb_uv_getnameinfo, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv, "gc", mrb_uv_gc, MRB_ARGS_NONE());
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
  mrb_define_module_function(mrb, _class_uv, "process_title=", mrb_uv_process_title_set, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv, "rusage", mrb_uv_rusage, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "cpu_info", mrb_uv_cpu_info, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "interface_addresses", mrb_uv_interface_addresses, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "queue_work", mrb_uv_queue_work, MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
  mrb_define_module_function(mrb, _class_uv, "resident_set_memory", mrb_uv_resident_set_memory, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "uptime", mrb_uv_uptime, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "get_error", mrb_uv_get_error, MRB_ARGS_REQ(1));
#if MRB_UV_CHECK_VERSION(1, 10, 0)
  mrb_define_module_function(mrb, _class_uv, "translate_sys_error", mrb_uv_translate_sys_error, MRB_ARGS_REQ(1));
#endif
#if MRB_UV_CHECK_VERSION(1, 12, 0)
  mrb_define_module_function(mrb, _class_uv, "osfhandle", mrb_uv_get_osfhandle, MRB_ARGS_REQ(1));
#endif

  mrb_define_const(mrb, _class_uv, "UV_RUN_DEFAULT", mrb_fixnum_value(UV_RUN_DEFAULT));
  mrb_define_const(mrb, _class_uv, "UV_RUN_ONCE", mrb_fixnum_value(UV_RUN_ONCE));
  mrb_define_const(mrb, _class_uv, "UV_RUN_NOWAIT", mrb_fixnum_value(UV_RUN_NOWAIT));
#ifdef _WIN32
  mrb_define_const(mrb, _class_uv, "IS_WINDOWS", mrb_true_value());
#else
  mrb_define_const(mrb, _class_uv, "IS_WINDOWS", mrb_false_value());
#endif
  mrb_define_const(mrb, _class_uv, "SOMAXCONN", mrb_fixnum_value(SOMAXCONN));
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_loop = mrb_define_class_under(mrb, _class_uv, "Loop", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_loop, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_loop, "initialize", mrb_uv_loop_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "run", mrb_uv_loop_run, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "delete", mrb_uv_loop_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "close", mrb_uv_loop_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "data=", mrb_uv_data_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "data", mrb_uv_data_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "alive?", mrb_uv_loop_alive, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "stop", mrb_uv_stop, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "update_time", mrb_uv_update_time, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "backend_fd", mrb_uv_backend_fd, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "backend_timeout", mrb_uv_backend_timeout, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_loop, "now", mrb_uv_now, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 12, 0)
  mrb_define_method(mrb, _class_uv_loop, "fork", mrb_uv_loop_fork, MRB_ARGS_NONE());
#endif
#if MRB_UV_CHECK_VERSION(1, 12, 2)
  mrb_define_method(mrb, _class_uv_loop, "configure", mrb_uv_loop_configure, MRB_ARGS_REQ(1));
#endif
  mrb_define_method(mrb, _class_uv_loop, "==", mrb_uv_loop_eq, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_loop, "make_current", mrb_uv_loop_make_current, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  def_loop = mrb_obj_value(mrb_data_object_alloc(mrb, _class_uv_loop, uv_default_loop(), &mrb_uv_loop_type));
  mrb_iv_set(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "default_loop"), def_loop);
  mrb_iv_set(mrb, mrb_obj_value(_class_uv), mrb_intern_lit(mrb, "current_loop"), def_loop);

  _class_uv_addrinfo = mrb_define_class_under(mrb, _class_uv, "Addrinfo", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_addrinfo, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_addrinfo, "flags", mrb_uv_addrinfo_flags, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "family", mrb_uv_addrinfo_family, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "socktype", mrb_uv_addrinfo_socktype, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "protocol", mrb_uv_addrinfo_protocol, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "addr", mrb_uv_addrinfo_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "canonname", mrb_uv_addrinfo_canonname, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_addrinfo, "next", mrb_uv_addrinfo_next, MRB_ARGS_NONE());

  mrb_define_const(mrb, _class_uv_addrinfo, "AF_INET", mrb_fixnum_value(AF_INET));
  mrb_define_const(mrb, _class_uv_addrinfo, "AF_INET6", mrb_fixnum_value(AF_INET6));
  mrb_define_const(mrb, _class_uv_addrinfo, "AF_UNSPEC", mrb_fixnum_value(AF_UNSPEC));
#ifdef AF_UNIX
  mrb_define_const(mrb, _class_uv_addrinfo, "AF_UNIX", mrb_fixnum_value(AF_UNIX));
#endif

  mrb_define_const(mrb, _class_uv_addrinfo, "SOCK_STREAM", mrb_fixnum_value(SOCK_STREAM));
  mrb_define_const(mrb, _class_uv_addrinfo, "SOCK_DGRAM", mrb_fixnum_value(SOCK_DGRAM));
  mrb_define_const(mrb, _class_uv_addrinfo, "SOCK_RAW", mrb_fixnum_value(SOCK_RAW));
  mrb_define_const(mrb, _class_uv_addrinfo, "SOCK_SEQPACKET", mrb_fixnum_value(SOCK_SEQPACKET));

  mrb_define_const(mrb, _class_uv_addrinfo, "AI_PASSIVE", mrb_fixnum_value(AI_PASSIVE));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_CANONNAME", mrb_fixnum_value(AI_CANONNAME));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_NUMERICHOST", mrb_fixnum_value(AI_NUMERICHOST));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_NUMERICSERV", mrb_fixnum_value(AI_NUMERICSERV));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_V4MAPPED", mrb_fixnum_value(AI_V4MAPPED));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_ALL", mrb_fixnum_value(AI_ALL));
  mrb_define_const(mrb, _class_uv_addrinfo, "AI_ADDRCONFIG", mrb_fixnum_value(AI_ADDRCONFIG));

  mrb_define_const(mrb, _class_uv_addrinfo, "IPPROTO_TCP", mrb_fixnum_value(IPPROTO_TCP));
  mrb_define_const(mrb, _class_uv_addrinfo, "IPPROTO_UDP", mrb_fixnum_value(IPPROTO_UDP));

  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip4addr = mrb_define_class_under(mrb, _class_uv, "Ip4Addr", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_ip4addr, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_ip4addr, "initialize", mrb_uv_ip4addr_init, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip4addr, "to_s", mrb_uv_ip4addr_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_addr", mrb_uv_ip4addr_sin_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "sin_port", mrb_uv_ip4addr_sin_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "addr", mrb_uv_ip4addr_sin_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip4addr, "port", mrb_uv_ip4addr_sin_port, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_ip6addr = mrb_define_class_under(mrb, _class_uv, "Ip6Addr", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_ip6addr, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_ip6addr, "initialize", mrb_uv_ip6addr_init, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_ip6addr, "to_s", mrb_uv_ip6addr_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "addr", mrb_uv_ip6addr_sin_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "port", mrb_uv_ip6addr_sin_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_addr", mrb_uv_ip6addr_sin_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "sin_port", mrb_uv_ip6addr_sin_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "scope_id", mrb_uv_ip6addr_sin6_scope_id, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 16, 0)
  mrb_define_method(mrb, _class_uv_ip6addr, "if_indextoname", mrb_uv_ip6addr_if_indextoname, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_ip6addr, "if_indextoiid", mrb_uv_ip6addr_if_indextoiid, MRB_ARGS_NONE());
#endif
  mrb_gc_arena_restore(mrb, ai);

#if MRB_UV_CHECK_VERSION(1, 16, 0)
  mrb_define_module_function(mrb, _class_uv, "if_indextoname", mrb_uv_if_indextoname, MRB_ARGS_NONE());
  mrb_define_module_function(mrb, _class_uv, "if_indextoiid", mrb_uv_if_indextoiid, MRB_ARGS_NONE());
#endif

  /* TODO
  uv_inet_ntop
  uv_inet_pton
  uv_replace_allocator
  */

  _class_uv_req = mrb_define_class_under(mrb, _class_uv, "Req", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_req, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_req, "cancel", mrb_uv_cancel, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_req, "type", mrb_uv_req_type, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_req, "type_name", mrb_uv_req_type_name, MRB_ARGS_NONE());
#if MRB_UV_CHECK_VERSION(1, 19, 0)
  mrb_define_method(mrb, _class_uv_req, "path", mrb_uv_fs_req_path, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_req, "result", mrb_uv_fs_req_result, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_req, "statbuf", mrb_uv_fs_req_statbuf, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_req, "type", mrb_uv_fs_req_type, MRB_ARGS_NONE());
#endif
  mrb_undef_class_method(mrb, _class_uv_req, "new");

  _class_uv_os = mrb_define_module_under(mrb, _class_uv, "OS");
#if MRB_UV_CHECK_VERSION(1, 6, 0)
  mrb_define_module_function(mrb, _class_uv_os, "homedir", mrb_uv_os_homedir, MRB_ARGS_NONE());
#endif
#if MRB_UV_CHECK_VERSION(1, 9, 0)
  mrb_define_module_function(mrb, _class_uv_os, "tmpdir", mrb_uv_os_tmpdir, MRB_ARGS_NONE());
#endif
#if MRB_UV_CHECK_VERSION(1, 12, 0)
  mrb_define_module_function(mrb, _class_uv_os, "getenv", mrb_uv_os_getenv, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_os, "setenv", mrb_uv_os_setenv, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_os, "unsetenv", mrb_uv_os_unsetenv, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_os, "hostname", mrb_uv_os_gethostname, MRB_ARGS_NONE());
#endif
#if MRB_UV_CHECK_VERSION(1, 16, 0)
  mrb_define_module_function(mrb, _class_uv_os, "getppid", mrb_uv_os_getppid, MRB_ARGS_NONE());
#endif
#if MRB_UV_CHECK_VERSION(1, 18, 0)
  mrb_define_module_function(mrb, _class_uv_os, "getpid", mrb_uv_os_getpid, MRB_ARGS_NONE());
#endif

#if MRB_UV_CHECK_VERSION(1, 9, 0)
  _class_uv_passwd = mrb_define_class_under(mrb, _class_uv_os, "Passwd", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_passwd, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_passwd, "initialize", mrb_uv_passwd_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_passwd, "username", mrb_uv_passwd_username, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_passwd, "shell", mrb_uv_passwd_shell, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_passwd, "homedir", mrb_uv_passwd_homedir, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_passwd, "uid", mrb_uv_passwd_uid, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_passwd, "gid", mrb_uv_passwd_gid, MRB_ARGS_NONE());
#endif

  mrb_mruby_uv_gem_init_fs(mrb, _class_uv);
  mrb_mruby_uv_gem_init_handle(mrb, _class_uv);
  mrb_mruby_uv_gem_init_thread(mrb, _class_uv);
  mrb_mruby_uv_gem_init_dl(mrb, _class_uv);

  mrb_define_const(mrb, _class_uv, "$GC", mrb_ary_new(mrb));
}

void
mrb_mruby_uv_gem_final(mrb_state* mrb) {
  // clear gc table
  mrb_uv_gc_table_clean(mrb, NULL);

  // run close callbacks to release objects related to mruby
  uv_walk(uv_default_loop(), mrb_uv_close_handle_belongs_to_vm, mrb);
  uv_run(uv_default_loop(), UV_RUN_ONCE);
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
