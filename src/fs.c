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
    return mrb_uv_from_uint64(mrb, st->st_ ## n);                       \
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
                       mrb_uv_from_uint64(mrb, st->st_ ## n.tv_sec),    \
                       mrb_uv_from_uint64(mrb, st->st_ ## n.tv_nsec / 1000)); \
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

#if MRB_UV_CHECK_VERSION(1, 28, 0)

static void
mrb_uv_dir_free(mrb_state *mrb, void *p)
{
  uv_fs_t req;
  uv_dir_t *dir = (uv_dir_t*)p;
  if (!dir) {
    return;
  }
  mrb_uv_check_error(mrb, uv_fs_closedir(uv_default_loop(), &req, dir, NULL));
}

static mrb_data_type const mrb_uv_dir_type = {
  "UV::Dir", mrb_uv_dir_free,
};

static mrb_value
dir_to_mrb(mrb_state *mrb, uv_dir_t *dir)
{
  struct RClass *dir_cls = mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "Dir");
  mrb_value ret = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, dir_cls));
  DATA_PTR(ret) = dir;
  DATA_TYPE(ret) = &mrb_uv_dir_type;
  return ret;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 31, 0)

static mrb_value
statfs_to_mrb(mrb_state *mrb, const uv_statfs_t *stat)
{
  mrb_value ret = mrb_hash_new(mrb);
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "type")), mrb_uv_from_uint64(mrb, stat->f_type));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "bsize")), mrb_uv_from_uint64(mrb, stat->f_bsize));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "blocks")), mrb_uv_from_uint64(mrb, stat->f_blocks));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "bfree")), mrb_uv_from_uint64(mrb, stat->f_bfree));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "bavail")), mrb_uv_from_uint64(mrb, stat->f_bavail));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "files")), mrb_uv_from_uint64(mrb, stat->f_files));
  mrb_hash_set(mrb, ret, mrb_symbol_value(mrb_intern_lit(mrb, "ffree")), mrb_uv_from_uint64(mrb, stat->f_ffree));
  return ret;
}

#endif

static mrb_value
dirtype_to_sym(mrb_state *mrb, uv_dirent_type_t t)
{
  mrb_sym ret;
  switch(t) {
  case UV_DIRENT_FILE: ret = mrb_intern_lit(mrb, "file"); break;
  case UV_DIRENT_DIR: ret = mrb_intern_lit(mrb, "dir"); break;
  case UV_DIRENT_LINK: ret = mrb_intern_lit(mrb, "link"); break;
  case UV_DIRENT_FIFO: ret = mrb_intern_lit(mrb, "fifo"); break;
  case UV_DIRENT_SOCKET: ret = mrb_intern_lit(mrb, "socket"); break;
  case UV_DIRENT_CHAR: ret = mrb_intern_lit(mrb, "char"); break;
  case UV_DIRENT_BLOCK: ret = mrb_intern_lit(mrb, "block"); break;

  default:
  case UV_DIRENT_UNKNOWN: ret = mrb_intern_lit(mrb, "unknown"); break;
  }
  return mrb_symbol_value(ret);
}

static mrb_value
dir_to_array(mrb_state *mrb, uv_fs_t *req)
{
  mrb_value ret = mrb_ary_new_capa(mrb, req->result);
  int ai = mrb_gc_arena_save(mrb);
  uv_dirent_t ent;

  while (uv_fs_scandir_next(req, &ent) != UV_EOF) {
    mrb_ary_push(mrb, ret, mrb_assoc_new(mrb, mrb_str_new_cstr(mrb, ent.name), dirtype_to_sym(mrb, ent.type)));
    mrb_gc_arena_restore(mrb, ai);
  }

  return ret;
}

static void
_uv_fs_cb(uv_fs_t* uv_req)
{
  mrb_uv_req_t* req = (mrb_uv_req_t*) uv_req->data;
  mrb_state* mrb = req->mrb;

  mrb_assert(!mrb_nil_p(req->block));

  if (uv_req->result < 0) {
    mrb_value const err = mrb_uv_create_error(mrb, uv_req->result);
    mrb_uv_req_yield(req, 1, &err);
    return;
  }

  switch (uv_req->fs_type) {
  case UV_FS_MKDTEMP: {
    mrb_value const str = mrb_str_new_cstr(mrb, uv_req->path);
    mrb_uv_req_yield(req, 1, &str);
  } break;

  case UV_FS_ACCESS: {
    mrb_value const arg = mrb_uv_create_status(mrb, uv_req->result);
    mrb_uv_req_yield(req, 1, &arg);
  } break;

#if MRB_UV_CHECK_VERSION(1, 14, 0)
  case UV_FS_COPYFILE: {
    mrb_uv_req_yield(req, 0, NULL);
  } break;
#endif

  case UV_FS_SCANDIR: {
    mrb_value const ary = dir_to_array(mrb, uv_req);
    mrb_uv_req_yield(req, 1, &ary);
  } break;

#if MRB_UV_CHECK_VERSION(1, 8, 0)
  case UV_FS_REALPATH:
#endif
  case UV_FS_READLINK: {
    mrb_value const res = mrb_str_new_cstr(mrb, uv_req->ptr);
    mrb_uv_req_yield(req, 1, &res);
  } break;

  case UV_FS_STAT:
  case UV_FS_FSTAT:
  case UV_FS_LSTAT: {
    mrb_value const res = mrb_uv_create_stat(mrb, &uv_req->statbuf);
    mrb_uv_req_yield(req, 1, &res);
  } break;

#if MRB_UV_CHECK_VERSION(1, 28, 0)
  case UV_FS_OPENDIR: {
    mrb_value const dir = dir_to_mrb(mrb, (uv_dir_t*)uv_req->ptr);
    mrb_uv_req_yield(req, 1, &dir);
  } break;
#endif

#if MRB_UV_CHECK_VERSION(1, 31, 0)
  case UV_FS_STATFS: {
    mrb_value const stat = statfs_to_mrb(mrb, (uv_statfs_t*)uv_req->ptr);
    mrb_uv_req_yield(req, 1, &stat);
  } break;
#endif

  default: {
      mrb_value const res = mrb_fixnum_value(uv_req->result);
      mrb_uv_req_yield(req, 1, &res);
    } break;
  }
}

static mrb_value
mrb_uv_fs_fd(mrb_state *mrb, mrb_value self)
{
  mrb_uv_file *ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  return mrb_fixnum_value(ctx->fd);
}

static mrb_value
mrb_uv_fs_path(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "path"));
}

static void
_uv_fs_open_cb(uv_fs_t* uv_req)
{
  mrb_uv_req_t *req = (mrb_uv_req_t*)uv_req->data;
  mrb_state* mrb = req->mrb;
  mrb_value args[2];
  mrb_uv_file *file;

  args[0] = mrb_iv_get(mrb, req->instance, mrb_intern_lit(mrb, "fs_open"));
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "fs_open"), mrb_nil_value());
  file = (mrb_uv_file*)DATA_PTR(args[0]);
  file->fd = uv_req->result;
  mrb_iv_set(mrb, args[0], mrb_intern_lit(mrb, "path"), mrb_str_new_cstr(mrb, uv_req->path));
  mrb_uv_req_yield(req, 2, args);
}

static mrb_value
mrb_uv_fs_open(mrb_state *mrb, mrb_value self)
{
  char const *arg_filename;
  mrb_value c, b, ret;
  mrb_int arg_flags, arg_mode;
  struct RClass* _class_uv_fs;
  mrb_uv_file* context;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&zii", &b, &arg_filename, &arg_flags, &arg_mode);

  _class_uv_fs = mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "FS");
  c = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, _class_uv_fs));
  context = (mrb_uv_file*)mrb_malloc(mrb, sizeof(mrb_uv_file));
  context->mrb = mrb;
  context->instance = c;
  context->fd = -1;
  DATA_PTR(c) = context;
  DATA_TYPE(c) = &mrb_uv_file_type;

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_open(mrb_uv_current_loop(mrb), &req->req.fs,
                   arg_filename, arg_flags, arg_mode, mrb_nil_p(req->block)? NULL : _uv_fs_open_cb);
  mrb_uv_req_check_error(mrb, req, res);
  if (mrb_nil_p(req->block)) {
    context->fd = res;
    mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "path"), mrb_str_new_cstr(mrb, arg_filename));
    return c;
  }
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "fs_open"), c);
  return ret;
}

#if MRB_UV_CHECK_VERSION(1, 34, 0)

static mrb_value
mrb_uv_fs_mkstemp(mrb_state *mrb, mrb_value self)
{
  char const *arg_filename;
  mrb_value c, b, ret;
  struct RClass* _class_uv_fs;
  mrb_uv_file* context;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&z", &b, &arg_filename);

  _class_uv_fs = mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "FS");
  c = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, _class_uv_fs));
  context = (mrb_uv_file*)mrb_malloc(mrb, sizeof(mrb_uv_file));
  context->mrb = mrb;
  context->instance = c;
  context->fd = -1;
  DATA_PTR(c) = context;
  DATA_TYPE(c) = &mrb_uv_file_type;

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_mkdtemp(mrb_uv_current_loop(mrb), &req->req.fs,
                      arg_filename, mrb_nil_p(req->block)? NULL : _uv_fs_open_cb);
  mrb_uv_req_check_error(mrb, req, res);
  if (mrb_nil_p(req->block)) {
    context->fd = res;
    mrb_iv_set(mrb, c, mrb_intern_lit(mrb, "path"), mrb_str_new_cstr(mrb, req->req.fs.path));
    return c;
  }
  mrb_iv_set(mrb, req->instance, mrb_intern_lit(mrb, "fs_open"), c);
  return ret;
}

#endif

static mrb_value
mrb_uv_fs_close(mrb_state *mrb, mrb_value self)
{
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&", &b);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_close(
      mrb_uv_current_loop(mrb), &req->req.fs, context->fd, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  if (mrb_nil_p(req->block)) {
    context->fd = -1;
  }
  return ret;
}

static mrb_value
mrb_uv_fs_write(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_data = mrb_nil_value();
  mrb_int arg_length = -1;
  mrb_int arg_offset = 0;
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b, ret;
  mrb_uv_req_t *req;
  uv_buf_t buf;
  int r;

  mrb_get_args(mrb, "&S|ii", &b, &arg_data, &arg_offset, &arg_length);

  if (arg_length == -1)
    arg_length = RSTRING_LEN(arg_data);
  if (arg_offset < 0)
    arg_offset = 0;
  mrb_str_resize(mrb, arg_data, arg_length);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_set_buf(req, &buf, arg_data);
  mrb_uv_req_check_error(mrb, req, r = uv_fs_write(
      mrb_uv_current_loop(mrb), &req->req.fs,
      context->fd, &buf, 1, arg_offset, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return mrb_nil_p(req->block)? mrb_fixnum_value(r) : ret;
}

static mrb_value
mrb_uv_fs_read(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_length = BUFSIZ, arg_offset = 0;
  mrb_uv_file* context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_value b, buf_str, ret;
  uv_buf_t buf;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&|ii", &b, &arg_length, &arg_offset);

  buf_str = mrb_str_resize(mrb, mrb_str_buf_new(mrb, arg_length), arg_length);
  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_set_buf(req, &buf, buf_str);
  res = uv_fs_read(mrb_uv_current_loop(mrb), &req->req.fs, context->fd,
                       &buf, 1, arg_offset, mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  mrb_uv_req_check_error(mrb, req, res);
  if (mrb_nil_p(req->block)) {
    mrb_str_resize(mrb, buf_str, res);
    return buf_str;
  }
  return ret;
}

static mrb_value
mrb_uv_fs_unlink(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&z", &b, &arg_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_unlink(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_path, mrb_nil_p(req->block)? NULL : _uv_fs_cb));

  return ret;
}

static mrb_value
mrb_uv_fs_mkdir(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_int arg_mode = 0755;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&z|i", &b, &arg_path, &arg_mode);
  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_mkdir(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_path, arg_mode,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_rmdir(mrb_state *mrb, mrb_value self)
{
  mrb_value arg_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&S", &b, &arg_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_rmdir(
      mrb_uv_current_loop(mrb), &req->req.fs, mrb_string_value_ptr(mrb, arg_path),
      mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_scandir(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_int arg_flags;
  mrb_value b, ret;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&zi", &b, &arg_path, &arg_flags);
  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_scandir(mrb_uv_current_loop(mrb), &req->req.fs, arg_path, arg_flags,
                      mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value ret = dir_to_array(mrb, &req->req.fs);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_fs_stat(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&z", &b, &arg_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_stat(mrb_uv_current_loop(mrb), &req->req.fs, arg_path,
                   mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->req.fs.statbuf);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_fs_fstat(mrb_state *mrb, mrb_value self)
{
  mrb_value b, ret;
  mrb_uv_req_t* req;
  mrb_uv_file *context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  int res;

  mrb_get_args(mrb, "&", &b);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_fstat(mrb_uv_current_loop(mrb), &req->req.fs, context->fd,
                    mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->req.fs.statbuf);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_fs_lstat(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;
  int res;

  mrb_get_args(mrb, "&z", &b, &arg_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_lstat(mrb_uv_current_loop(mrb), &req->req.fs, arg_path,
                    mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value ret = mrb_uv_create_stat(mrb, &req->req.fs.statbuf);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_fs_rename(mrb_state *mrb, mrb_value self)
{
  char const *arg_path, *arg_new_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&zz", &b, &arg_path, &arg_new_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_rename(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_path, arg_new_path, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_fsync(mrb_state *mrb, mrb_value self)
{
  mrb_value b, ret;
  mrb_uv_file *context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&", &b);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_fsync(
      mrb_uv_current_loop(mrb), &req->req.fs, context->fd, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_fdatasync(mrb_state *mrb, mrb_value self)
{
  mrb_value b, ret;
  mrb_uv_file *context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&", &b);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_fdatasync(
      mrb_uv_current_loop(mrb), &req->req.fs, context->fd, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_ftruncate(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_offset;
  mrb_value b, ret;
  mrb_uv_file *context = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&i", &b, &arg_offset);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_ftruncate(
      mrb_uv_current_loop(mrb), &req->req.fs, context->fd, arg_offset,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_sendfile(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_outfd, arg_infd, arg_offset, arg_length;
  mrb_value b, outfile, infile, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&ooii", &b, &infile, &outfile, &arg_offset, &arg_length);
  arg_infd = mrb_uv_to_fd(mrb, infile);
  arg_outfd = mrb_uv_to_fd(mrb, outfile);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_sendfile(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_infd, arg_outfd, arg_offset, arg_length,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_chmod(mrb_state *mrb, mrb_value self)
{
  char const *arg_path;
  mrb_int arg_mode;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&zi", &b, &arg_path, &arg_mode);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_chmod(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_path, arg_mode, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_link(mrb_state *mrb, mrb_value self)
{
  char const *arg_path, *arg_new_path;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&zz", &b, &arg_path, &arg_new_path);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_link(
      mrb_uv_current_loop(mrb), &req->req.fs, arg_path, arg_new_path, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_utime(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_float atime, mtime;
  mrb_value b, ret;
  mrb_uv_req_t* req;

  mrb_get_args(mrb, "&zff", &b, &path, &atime, &mtime);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_utime(
      mrb_uv_current_loop(mrb), &req->req.fs, path, (double)atime, (double)mtime,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_futime(mrb_state *mrb, mrb_value self)
{
  mrb_float atime, mtime;
  mrb_value b, ret;
  mrb_uv_file *ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&ff", &b, &atime, &mtime);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_futime(
      mrb_uv_current_loop(mrb), &req->req.fs, ctx->fd,
      (double)atime, (double)mtime, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_fchmod(mrb_state *mrb, mrb_value self)
{
  mrb_int mode;
  mrb_value b, ret;
  mrb_uv_file *ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&i", &b, &mode);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_fchmod(
      mrb_uv_current_loop(mrb), &req->req.fs, ctx->fd, mode, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_symlink(mrb_state *mrb, mrb_value self)
{
  char const *path, *new_path;
  mrb_int flags = 0;
  mrb_value b, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&zz|i", &b, &path, &new_path, &flags);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_symlink(
      mrb_uv_current_loop(mrb), &req->req.fs, path, new_path, flags, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_readlink(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_value b, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&z", &b, &path);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_readlink(
      mrb_uv_current_loop(mrb), &req->req.fs, path, mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value const ret = mrb_str_new_cstr(mrb, req->req.fs.ptr);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#if MRB_UV_CHECK_VERSION(1, 8, 0)

static mrb_value
mrb_uv_fs_realpath(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_value b, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&z", &b, &path);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_realpath(mrb_uv_current_loop(mrb), &req->req.fs, path,
                       mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block)) {
    mrb_value const ret = mrb_str_new_cstr(mrb, req->req.fs.ptr);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#endif

static mrb_value
mrb_uv_fs_chown(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_int uid, gid;
  mrb_value b, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&zii", &b, &path, &uid, &gid);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_chown(
      mrb_uv_current_loop(mrb), &req->req.fs, path,
      (uv_uid_t)uid, (uv_gid_t)gid, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_fchown(mrb_state *mrb, mrb_value self)
{
  mrb_int uid, gid;
  mrb_value b, ret;
  mrb_uv_file *ctx = (mrb_uv_file*)mrb_uv_get_ptr(mrb, self, &mrb_uv_file_type);
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&ii", &b, &uid, &gid);

  req = mrb_uv_req_current(mrb, b, &ret);
  mrb_uv_req_check_error(mrb, req, uv_fs_fchown(
      mrb_uv_current_loop(mrb), &req->req.fs, ctx->fd,
      (uv_uid_t)uid, (uv_gid_t)gid, mrb_nil_p(req->block)? NULL : _uv_fs_cb));
  return ret;
}

static mrb_value
mrb_uv_fs_mkdtemp(mrb_state *mrb, mrb_value self)
{
  char const *tmp;
  mrb_value b, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&z", &b, &tmp);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_mkdtemp(mrb_uv_current_loop(mrb), &req->req.fs,
                      tmp, mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block) && res >= 0) {
    mrb_value const ret = mrb_str_new_cstr(mrb, req->req.fs.path);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_fs_access(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_int flags;
  int res;
  mrb_value b, ret;
  mrb_uv_req_t *req;

  mrb_get_args(mrb, "&zi", &b, &path, &flags);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_access(mrb_uv_current_loop(mrb), &req->req.fs, path, flags,
                     mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    return mrb_uv_create_status(mrb, res);
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#if MRB_UV_CHECK_VERSION(1, 14, 0)

static mrb_value
mrb_uv_fs_copyfile(mrb_state *mrb, mrb_value self)
{
  const char *old_path, *new_path;
  mrb_int flags = 0;
  mrb_value proc, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&zz|i", &proc, &old_path, &new_path, &flags);
  req = mrb_uv_req_current(mrb, proc, &ret);
  res = uv_fs_copyfile(
      mrb_uv_current_loop(mrb), &req->req.fs, old_path, new_path, flags,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    return mrb_uv_create_status(mrb, res);
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 21, 0)

static mrb_value
mrb_uv_fs_lchown(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_value b, ret;
  mrb_uv_req_t *req;
  int res, uid, gid;

  mrb_get_args(mrb, "&zii", &b, &path, &uid, &gid);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_lchown(mrb_uv_current_loop(mrb), &req->req.fs, path, uid, gid,
                     mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block)) {
    mrb_value const ret = mrb_str_new_cstr(mrb, req->req.fs.ptr);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 28, 0)

static mrb_value
mrb_uv_fs_opendir(mrb_state* mrb, mrb_value self) {
  const char *path;
  mrb_value proc, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&z", &proc, &path);
  req = mrb_uv_req_current(mrb, proc, &ret);
  res = uv_fs_opendir(
      mrb_uv_current_loop(mrb), &req->req.fs, path,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    return mrb_uv_create_status(mrb, res);
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_dir_read(mrb_state* mrb, mrb_value self) {
  mrb_value proc, ret;
  mrb_uv_req_t *req;
  int res;
  uv_dir_t *dir = (uv_dir_t*)mrb_data_get_ptr(mrb, self, &mrb_uv_dir_type);

  mrb_get_args(mrb, "&", &proc);
  req = mrb_uv_req_current(mrb, proc, &ret);
  res = uv_fs_readdir(
      mrb_uv_current_loop(mrb), &req->req.fs, dir,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    return mrb_uv_create_status(mrb, res);
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

static mrb_value
mrb_uv_dir_close(mrb_state* mrb, mrb_value self) {
  mrb_value proc, ret;
  mrb_uv_req_t *req;
  int res;
  uv_dir_t *dir = (uv_dir_t*)mrb_data_get_ptr(mrb, self, &mrb_uv_dir_type);

  mrb_get_args(mrb, "&", &proc);
  req = mrb_uv_req_current(mrb, proc, &ret);
  res = uv_fs_closedir(
      mrb_uv_current_loop(mrb), &req->req.fs, dir,
      mrb_nil_p(req->block)? NULL : _uv_fs_cb);
  if (mrb_nil_p(req->block)) {
    mrb_uv_req_clear(req);
    return mrb_uv_create_status(mrb, res);
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#endif

#if MRB_UV_CHECK_VERSION(1, 31, 0)

static mrb_value
mrb_uv_fs_statfs(mrb_state *mrb, mrb_value self)
{
  char const *path;
  mrb_value b, ret;
  mrb_uv_req_t *req;
  int res;

  mrb_get_args(mrb, "&z", &b, &path);

  req = mrb_uv_req_current(mrb, b, &ret);
  res = uv_fs_statfs(mrb_uv_current_loop(mrb), &req->req.fs, path,
                     mrb_nil_p(req->block)? NULL : _uv_fs_cb);

  if (mrb_nil_p(req->block)) {
    mrb_value const ret = statfs_to_mrb(mrb, (uv_statfs_t*)req->req.fs.ptr);
    mrb_uv_req_clear(req);
    return ret;
  }
  mrb_uv_req_check_error(mrb, req, res);
  return ret;
}

#endif

void mrb_mruby_uv_gem_init_fs(mrb_state *mrb, struct RClass *UV)
{
  struct RClass *_class_uv_fs;
  struct RClass *_class_uv_stat;
  struct RClass *_class_uv_dir;

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
  mrb_define_const(mrb, _class_uv_fs, "S_IWRITE", mrb_fixnum_value(S_IWUSR));
  mrb_define_const(mrb, _class_uv_fs, "S_IREAD", mrb_fixnum_value(S_IRUSR));
  mrb_define_const(mrb, _class_uv_fs, "S_IEXEC", mrb_fixnum_value(S_IXUSR));
  mrb_define_const(mrb, _class_uv_fs, "F_OK", mrb_fixnum_value(F_OK));
  mrb_define_const(mrb, _class_uv_fs, "R_OK", mrb_fixnum_value(R_OK));
  mrb_define_const(mrb, _class_uv_fs, "W_OK", mrb_fixnum_value(W_OK));
  mrb_define_const(mrb, _class_uv_fs, "X_OK", mrb_fixnum_value(X_OK));
#if MRB_UV_CHECK_VERSION(1, 14, 0)
  mrb_define_const(mrb, _class_uv_fs, "COPYFILE_EXCL", mrb_fixnum_value(UV_FS_COPYFILE_EXCL));
#endif
#if MRB_UV_CHECK_VERSION(1, 20, 0)
  mrb_define_const(mrb, _class_uv_fs, "COPYFILE_FICLONE", mrb_fixnum_value(UV_FS_COPYFILE_FICLONE));
  mrb_define_const(mrb, _class_uv_fs, "COPYFILE_FICLONE_FORCE", mrb_fixnum_value(UV_FS_COPYFILE_FICLONE_FORCE));
#endif
  mrb_define_method(mrb, _class_uv_fs, "write", mrb_uv_fs_write, MRB_ARGS_REQ(1) | MRB_ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_fs, "read", mrb_uv_fs_read, MRB_ARGS_REQ(0) | MRB_ARGS_OPT(2));
  mrb_define_method(mrb, _class_uv_fs, "datasync", mrb_uv_fs_fdatasync, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs, "truncate", mrb_uv_fs_ftruncate, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_fs, "stat", mrb_uv_fs_fstat, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs, "sync", mrb_uv_fs_fsync, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs, "chmod", mrb_uv_fs_fchmod, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_fs, "utime", mrb_uv_fs_futime, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs, "chown", mrb_uv_fs_fchown, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _class_uv_fs, "close", mrb_uv_fs_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs, "fd", mrb_uv_fs_fd, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_fs, "path", mrb_uv_fs_path, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, _class_uv_fs, "open", mrb_uv_fs_open, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "unlink", mrb_uv_fs_unlink, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "mkdir", mrb_uv_fs_mkdir, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "rmdir", mrb_uv_fs_rmdir, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "scandir", mrb_uv_fs_scandir, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "stat", mrb_uv_fs_stat, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "rename", mrb_uv_fs_rename, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "sendfile", mrb_uv_fs_sendfile, MRB_ARGS_REQ(4));
  mrb_define_class_method(mrb, _class_uv_fs, "chmod", mrb_uv_fs_chmod, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "lstat", mrb_uv_fs_lstat, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "link", mrb_uv_fs_link, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "utime", mrb_uv_fs_utime, MRB_ARGS_REQ(3));
  mrb_define_class_method(mrb, _class_uv_fs, "symlink", mrb_uv_fs_symlink, MRB_ARGS_REQ(3));
  mrb_define_class_method(mrb, _class_uv_fs, "readlink", mrb_uv_fs_readlink, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "chown", mrb_uv_fs_chown, MRB_ARGS_REQ(3));
  mrb_define_class_method(mrb, _class_uv_fs, "mkdtemp", mrb_uv_fs_mkdtemp, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_fs, "access", mrb_uv_fs_access, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, _class_uv_fs, "scandir", mrb_uv_fs_scandir, MRB_ARGS_REQ(2));
#if MRB_UV_CHECK_VERSION(1, 14, 0)
  mrb_define_class_method(mrb, _class_uv_fs, "copyfile", mrb_uv_fs_copyfile, MRB_ARGS_REQ(2) | MRB_ARGS_OPT(1));
#endif
#if MRB_UV_CHECK_VERSION(1, 8, 0)
  mrb_define_class_method(mrb, _class_uv_fs, "realpath", mrb_uv_fs_realpath, MRB_ARGS_REQ(1));
#endif
#if MRB_UV_CHECK_VERSION(1, 21, 0)
  mrb_define_class_method(mrb, _class_uv_fs, "lchown", mrb_uv_fs_lchown, MRB_ARGS_REQ(3));
#endif
#if MRB_UV_CHECK_VERSION(1, 28, 0)
  _class_uv_dir = mrb_define_class_under(mrb, UV, "Dir", mrb->object_class);
  mrb_define_class_method(mrb, _class_uv_fs, "opendir", mrb_uv_fs_opendir, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_dir, "read", mrb_uv_dir_read, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, _class_uv_dir, "close", mrb_uv_dir_close, MRB_ARGS_BLOCK());
#endif
#if MRB_UV_CHECK_VERSION(1, 31, 0)
  mrb_define_class_method(mrb, _class_uv_fs, "statfs", mrb_uv_fs_statfs, MRB_ARGS_REQ(1));
#endif
#if MRB_UV_CHECK_VERSION(1, 34, 0)
  mrb_define_class_method(mrb, _class_uv_fs, "mkstemp", mrb_uv_fs_mkstemp, MRB_ARGS_REQ(1));
#endif

  /* for compatibility */
  mrb_define_class_method(mrb, _class_uv_fs, "readdir", mrb_uv_fs_scandir, MRB_ARGS_REQ(2));

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

#if MRB_UV_CHECK_VERSION(1, 28, 0)
  _class_uv_dir = mrb_define_class_under(mrb, UV, "Dir", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_dir, MRB_TT_DATA);
  mrb_undef_class_method(mrb, _class_uv_dir, "new");
  mrb_define_method(mrb, _class_uv_dir, "close", mrb_uv_dir_close, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _class_uv_dir, "readdir", mrb_uv_dir_read, MRB_ARGS_OPT(1));
#endif
}
