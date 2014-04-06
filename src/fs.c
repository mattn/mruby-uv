#include "mruby/uv.h"
#include "mrb_uv.h"
#include <fcntl.h>

/*
 * UV::Stat
 */
static void
mrb_uv_stat_free(mrb_state *mrb, void *p)
{
  mrb_free(mrb, p);
}

static struct mrb_data_type const mrb_uv_stat_type = {
  "uv_stat", mrb_uv_stat_free
};

mrb_value
mrb_uv_create_stat(mrb_state *mrb, uv_stat_t const *src_st)
{
  uv_stat_t *st;
  struct RClass *cls;

  cls = mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "Stat");
  st = (uv_stat_t*)mrb_malloc(mrb, sizeof(uv_stat_t));
  *st = *src_st; /* copy */
  return mrb_obj_value(mrb_data_object_alloc(mrb, cls, st, &mrb_uv_stat_type));
}

#define stat_field(n)                                                   \
  static mrb_value                                                      \
  mrb_uv_stat_ ## n(mrb_state *mrb, mrb_value self)                     \
  {                                                                     \
    uv_stat_t *st = (uv_stat_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_stat_type); \
    return mrb_float_value(mrb, (mrb_float)st->st_ ## n);               \
  }                                                                     \

stat_field(dev)
stat_field(mode)
stat_field(nlink)
stat_field(uid)
stat_field(gid)
stat_field(rdev)
stat_field(ino)
stat_field(size)
stat_field(blksize)
stat_field(blocks)
stat_field(flags)
stat_field(gen)

#undef stat_field

#define stat_time_field(n)                                              \
  static mrb_value                                                      \
  mrb_uv_stat_ ## n(mrb_state *mrb, mrb_value self)                     \
  {                                                                     \
    uv_stat_t *st = (uv_stat_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_stat_type); \
    return mrb_funcall(mrb, mrb_obj_value(mrb_class_get(mrb, "Time")), "at", 2, \
                       mrb_float_value(mrb, (mrb_float)st->st_ ## n.tv_sec), \
                       mrb_float_value(mrb, (mrb_float)(st->st_ ## n.tv_nsec / 1000))); \
  }                                                                     \

stat_time_field(atim)
stat_time_field(mtim)
stat_time_field(ctim)
stat_time_field(birthtim)

#undef stat_time_field

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

uv_file
mrb_uv_to_fd(mrb_state *mrb, mrb_value v)
{
  if (mrb_fixnum_p(v)) {
    return mrb_fixnum(v);
  }

  return ((mrb_uv_file*)mrb_uv_get_ptr(mrb, v, &mrb_uv_file_type))->fd;
}

static void
_uv_fs_open_cb(uv_fs_t* req)
{
  mrb_uv_file *context = (mrb_uv_file*)req->data;
  mrb_state* mrb = context->mrb;
  mrb_value proc;
  mrb_uv_check_error(mrb, req->result);
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
  mrb_uv_check_error(mrb, req->result);
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

  case UV_FS_READLINK: {
    mrb_value res;
    mrb_assert(!mrb_nil_p(proc));
    res = mrb_str_new_cstr(mrb, req->ptr);
    mrb_yield_argv(mrb, proc, 1, &res);
  } break;

  case UV_FS_STAT:
  case UV_FS_FSTAT:
  case UV_FS_LSTAT: {
    mrb_value res;
    mrb_assert(!mrb_nil_p(proc));
    res = mrb_uv_create_stat(mrb, &req->statbuf);
    mrb_yield_argv(mrb, proc, 1, &res);
  } break;

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
      DATA_PTR(context->instance) = NULL;
      mrb_free(mrb, context);
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
  mrb_uv_file *ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
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
    mrb_uv_check_error(mrb, context->fd);
  }

  mrb_uv_gc_protect(mrb, c);
  return c;
}

static mrb_value
mrb_uv_fs_close(mrb_state *mrb, mrb_value self)
{
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;

  mrb_get_args(mrb, "&", &b);
  if (mrb_nil_p(b)) {
    fs_cb = NULL;
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  memset(req, 0, sizeof(uv_fs_t));
  req->data = context;
  uv_fs_close(uv_default_loop(), req, context->fd, fs_cb);
  return self;
}

static mrb_value
mrb_uv_fs_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value();
  mrb_int arg_length = -1;
  mrb_int arg_offset = 0;
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_fs_t* req;
  int r;
  uv_buf_t buf;

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
    mrb_uv_check_error(mrb, r);
  }
  return mrb_fixnum_value(r);
}

static mrb_value
mrb_uv_fs_read(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_length = BUFSIZ;
  mrb_int arg_offset = 0;
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b = mrb_nil_value();
  uv_fs_cb fs_cb = _uv_fs_cb;
  uv_buf_t buf;
  int len;
  uv_fs_t* req;
  int ai;
  mrb_value str;

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
    mrb_uv_check_error(mrb, len);
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_fs_readdir(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_value arg_path;
  mrb_int arg_flags;
  mrb_value b = mrb_nil_value();
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&Si", &b, &arg_path, &arg_flags);
  if (!mrb_nil_p(b)) {
    context.mrb = mrb;
    context.instance = self;
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
  }

  req = (uv_fs_t*) mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_readdir(uv_default_loop(), req, mrb_string_value_ptr(mrb, arg_path),
                      arg_flags, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }
  if (mrb_nil_p(b)) {
    int i;
    char *ptr = (char*)req->ptr;
    mrb_value const ret = mrb_ary_new_capa(mrb, req->result);
    for (i = 0; i < req->result; ++i) {
      mrb_ary_push(mrb, ret, mrb_str_new_cstr(mrb, ptr));
      ptr += strlen(ptr) + 1;
    }
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
    return ret;
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->statbuf);
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
    return ret;
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->statbuf);
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
    return ret;
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->statbuf);
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
    return ret;
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_fs_sendfile(mrb_state *mrb, mrb_value self)
{
  int err;
  mrb_int arg_outfd, arg_infd, arg_offset, arg_length;
  mrb_value b = mrb_nil_value(), outfile, infile;
  uv_fs_cb fs_cb = _uv_fs_cb;
  static mrb_uv_file context;
  uv_fs_t* req;

  mrb_get_args(mrb, "&ooii", &b, &infile, &outfile, &arg_offset, &arg_length);
  arg_infd = mrb_uv_to_fd(mrb, infile);
  arg_outfd = mrb_uv_to_fd(mrb, outfile);
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
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
    mrb_uv_check_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_fs_utime(mrb_state *mrb, mrb_value self)
{
  char *path;
  mrb_value b;
  static mrb_uv_file context;
  uv_fs_t *req;
  mrb_float atime, mtime;
  int err;

  mrb_get_args(mrb, "&zff", &b, &path, &atime, &mtime);

  if (!mrb_nil_p(b)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
    context.mrb = mrb;
    context.instance = self;
    context.fd = -1;
  }

  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = &context;
  err = uv_fs_utime(uv_default_loop(), req, path, (double)atime, (double)mtime, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }
  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

static mrb_value
mrb_uv_fs_futime(mrb_state *mrb, mrb_value self)
{
  mrb_float atime, mtime;
  mrb_value b;
  mrb_uv_file *ctx;
  uv_fs_t *req;
  int err;

  mrb_get_args(mrb, "&ff", &b, &atime, &mtime);

  if (!mrb_nil_p(b)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
  }

  ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = ctx;
  err = uv_fs_futime(uv_default_loop(), req, ctx->fd, (double)atime, (double)mtime, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }
  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

static mrb_value
mrb_uv_fs_fchmod(mrb_state *mrb, mrb_value self)
{
  mrb_int mode;
  mrb_value b;
  mrb_uv_file *ctx;
  uv_fs_t *req;
  int err;

  mrb_get_args(mrb, "&i", &b, &mode);

  if (!mrb_nil_p(b)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
  }

  ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = ctx;
  err = uv_fs_fchmod(uv_default_loop(), req, ctx->fd, mode, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

static mrb_value
mrb_uv_fs_symlink(mrb_state *mrb, mrb_value self)
{
  char *path, *new_path;
  mrb_int flags;
  mrb_value b;
  uv_fs_t *req;
  int err;
  static mrb_uv_file ctx;

  mrb_get_args(mrb, "&zzi", &b, &path, &new_path, &flags);

  if (!mrb_nil_p(b)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
    ctx.mrb = mrb;
    ctx.instance = self;
    ctx.fd = -1;
  }

  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = &ctx;
  err = uv_fs_symlink(uv_default_loop(), req, path, new_path, flags, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

static mrb_value
mrb_uv_fs_readlink(mrb_state *mrb, mrb_value self)
{
  char *path;
  mrb_value b;
  static mrb_uv_file ctx;
  uv_fs_t *req;
  int err;

  mrb_get_args(mrb, "&z", &b, &path);

  if (!mrb_nil_p(b)) {
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "fs_cb"), b);
    ctx.mrb = mrb;
    ctx.instance = self;
    ctx.fd = -1;
  }

  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = &ctx;
  err = uv_fs_readlink(uv_default_loop(), req, path, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    mrb_value const ret = mrb_str_new_cstr(mrb, req->ptr);
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
    return ret;
  }
  return self;
}

static mrb_value
mrb_uv_fs_chown(mrb_state *mrb, mrb_value self)
{
  char *path;
  mrb_int uid, gid;
  mrb_value b;
  uv_fs_t *req;
  int err;
  static mrb_uv_file ctx;

  mrb_get_args(mrb, "&zii", &b, &path, &uid, &gid);

  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = &ctx;
  err = uv_fs_chown(uv_default_loop(), req, path, (uv_uid_t)uid, (uv_gid_t)gid, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

static mrb_value
mrb_uv_fs_fchown(mrb_state *mrb, mrb_value self)
{
  mrb_int uid, gid;
  mrb_value b;
  mrb_uv_file *ctx;
  uv_fs_t *req;
  int err;

  mrb_get_args(mrb, "&ii", &b, &uid, &gid);

  ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  req = (uv_fs_t*)mrb_malloc(mrb, sizeof(uv_fs_t));
  req->data = ctx;
  err = uv_fs_fchown(uv_default_loop(), req, ctx->fd, (uv_uid_t)uid, (uv_gid_t)gid, mrb_nil_p(b)? NULL : _uv_fs_cb);
  if (err < 0) {
    mrb_free(mrb, req);
    mrb_uv_check_error(mrb, err);
  }

  if (mrb_nil_p(b)) {
    uv_fs_req_cleanup(req);
    mrb_free(mrb, req);
  }
  return self;
}

void mrb_mruby_uv_gem_init_fs(mrb_state *mrb, struct RClass *UV)
{
  struct RClass *_class_uv_fs;
  struct RClass *_class_uv_stat;

  _class_uv_fs = mrb_define_class_under(mrb, UV, "FS", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_fs, MRB_TT_DATA);
  mrb_define_const(mrb, _class_uv_fs, "SYMLINK_DIR", mrb_fixnum_value(UV_FS_SYMLINK_DIR));
  mrb_define_const(mrb, _class_uv_fs, "SYMLINK_JUNCTION", mrb_fixnum_value(UV_FS_SYMLINK_JUNCTION));
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
  mrb_define_method(mrb, _class_uv_fs, "chmod", mrb_uv_fs_fchmod, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "lstat", mrb_uv_fs_lstat, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "link", mrb_uv_fs_link, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "utime", mrb_uv_fs_utime, ARGS_REQ(3));
  mrb_define_method(mrb, _class_uv_fs, "futime", mrb_uv_fs_futime, ARGS_REQ(2));
  mrb_define_module_function(mrb, _class_uv_fs, "symlink", mrb_uv_fs_symlink, ARGS_REQ(3));
  mrb_define_module_function(mrb, _class_uv_fs, "readlink", mrb_uv_fs_readlink, ARGS_REQ(1));
  mrb_define_module_function(mrb, _class_uv_fs, "chown", mrb_uv_fs_chown, ARGS_REQ(3));
  mrb_define_method(mrb, _class_uv_fs, "chown", mrb_uv_fs_fchown, ARGS_REQ(2));

  _class_uv_stat = mrb_define_class_under(mrb, UV, "Stat", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_stat, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_stat, "dev", mrb_uv_stat_dev, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "mode", mrb_uv_stat_mode, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "nlink", mrb_uv_stat_nlink, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "uid", mrb_uv_stat_uid, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "gid", mrb_uv_stat_gid, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "rdev", mrb_uv_stat_rdev, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "ino", mrb_uv_stat_ino, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "size", mrb_uv_stat_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "blksize", mrb_uv_stat_blksize, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "blocks", mrb_uv_stat_blocks, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "flags", mrb_uv_stat_flags, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "gen", mrb_uv_stat_gen, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "atim", mrb_uv_stat_atim, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "mtim", mrb_uv_stat_mtim, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "ctim", mrb_uv_stat_ctim, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_stat, "birthtim", mrb_uv_stat_birthtim, MRB_ARGS_NONE());
  /* cannot create from mruby side */
  mrb_undef_class_method(mrb, _class_uv_stat, "new");
}
