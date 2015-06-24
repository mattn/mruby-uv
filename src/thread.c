#include "mruby/uv.h"
#include "mrb_uv.h"


/*********************************************************
 * UV::Mutex
 *********************************************************/
void
mrb_uv_mutex_free(mrb_state *mrb, void *p)
{
  if (p) {
    uv_mutex_destroy((uv_mutex_t*)p);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type mrb_uv_mutex_type = {
  "uv_mutex", mrb_uv_mutex_free
};

static mrb_value
mrb_uv_mutex_init(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_malloc(mrb, sizeof(uv_mutex_t));
  mrb_uv_check_error(mrb, uv_mutex_init(m));
  DATA_PTR(self) = m;
  DATA_TYPE(self) = &mrb_uv_mutex_type;
  return self;
}

static mrb_value
mrb_uv_mutex_lock(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type);
  uv_mutex_lock(m);
  return self;
}

static mrb_value
mrb_uv_mutex_unlock(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type);
  uv_mutex_unlock(m);
  return self;
}

static mrb_value
mrb_uv_mutex_trylock(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(uv_mutex_trylock((uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type)));
}

static mrb_value
mrb_uv_mutex_destroy(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type);
  uv_mutex_destroy(m);
  mrb_free(mrb, m);
  DATA_PTR(self) = NULL;
  return self;
}

/*********************************************************
 * UV::Thread
 *********************************************************/
typedef struct {
  mrb_state *mrb;
  mrb_value instance;
  uv_thread_t thread;
} mrb_uv_thread;

static void
mrb_uv_thread_free(mrb_state *mrb, void *p)
{
  if (p) {
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type mrb_uv_thread_type = {
  "uv_thread", mrb_uv_thread_free
};

static void
_uv_thread_proc(void *arg)
{
  mrb_uv_thread* context = (mrb_uv_thread*) arg;
  mrb_state* mrb = context->mrb;
  mrb_value proc, thread_arg;
  if (!mrb) return;
  proc = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "thread_proc"));
  thread_arg = mrb_iv_get(mrb, context->instance, mrb_intern_lit(mrb, "thread_arg"));
  if (!mrb_nil_p(proc)) {
    mrb_value args[1];
    args[0] = thread_arg;
    mrb_yield_argv(mrb, proc, 1, args);
  }
}

static mrb_value
mrb_uv_thread_init(mrb_state *mrb, mrb_value self)
{
  mrb_value thread_arg = mrb_nil_value();
  mrb_value b = mrb_nil_value();
  mrb_uv_thread* context = NULL;

  mrb_get_args(mrb, "&|o", &b, &thread_arg);

  context = (mrb_uv_thread*)mrb_malloc(mrb, sizeof(mrb_uv_thread));
  context->mrb = mrb;
  context->instance = self;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "thread_proc"), b);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "thread_arg"), thread_arg);
  DATA_PTR(self) = context;
  DATA_TYPE(self) = &mrb_uv_thread_type;

  mrb_uv_check_error(mrb, uv_thread_create(&context->thread, _uv_thread_proc, context));
  return self;
}

static mrb_value
mrb_uv_thread_join(mrb_state *mrb, mrb_value self)
{
  mrb_uv_thread* context = NULL;

  Data_Get_Struct(mrb, self, &mrb_uv_thread_type, context);

  uv_thread_join(&context->thread);
  return self;
}

static mrb_value
mrb_uv_thread_self(mrb_state *mrb, mrb_value self)
{
  mrb_uv_thread *ctx;

  ctx = (mrb_uv_thread*)mrb_malloc(mrb, sizeof(mrb_uv_thread));
  ctx->instance = mrb_nil_value();
  ctx->mrb = mrb;
  ctx->thread = uv_thread_self();

  return mrb_obj_value(Data_Wrap_Struct(
      mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "UV"), "Thread"),
      &mrb_uv_thread_type, ctx));
}

static mrb_value
mrb_uv_thread_eq(mrb_state *mrb, mrb_value self)
{
  mrb_uv_thread *self_ctx = NULL, *other_ctx = NULL;
  mrb_value other;

  mrb_get_args(mrb, "o", &other);

  Data_Get_Struct(mrb, self, &mrb_uv_thread_type, self_ctx);
  Data_Get_Struct(mrb, other, &mrb_uv_thread_type, other_ctx);

  return mrb_bool_value(uv_thread_equal(&self_ctx->thread, &other_ctx->thread));
}

/*********************************************************
 * UV::Barrier
 *********************************************************/
static void
mrb_uv_barrier_free(mrb_state *mrb, void *p)
{
  if(p) {
    uv_barrier_destroy((uv_barrier_t*)p);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type barrier_type = {
  "uv_barrier", mrb_uv_barrier_free
};

static mrb_value
mrb_uv_barrier_init(mrb_state *mrb, mrb_value self)
{
  mrb_int arg_count;
  uv_barrier_t* context = NULL;

  mrb_get_args(mrb, "i", &arg_count);

  context = (uv_barrier_t*)mrb_malloc(mrb, sizeof(uv_barrier_t));

  mrb_uv_check_error(mrb, uv_barrier_init(context, arg_count));
  DATA_PTR(self) = context;
  DATA_TYPE(self) = &barrier_type;
  return self;
}

static mrb_value
mrb_uv_barrier_wait(mrb_state *mrb, mrb_value self)
{
  uv_barrier_wait((uv_barrier_t*)mrb_uv_get_ptr(mrb, self, &barrier_type));
  return self;
}

static mrb_value
mrb_uv_barrier_destroy(mrb_state *mrb, mrb_value self)
{
  uv_barrier_destroy((uv_barrier_t*)mrb_uv_get_ptr(mrb, self, &barrier_type));
  mrb_free(mrb, DATA_PTR(self));
  DATA_PTR(self) = NULL;
  return self;
}

void
mrb_uv_sem_free(mrb_state *mrb, void *p)
{
  if(!p) { return; }

  uv_sem_destroy((uv_sem_t*)p);
  mrb_free(mrb, p);
}

static struct mrb_data_type sem_type = {
  "uv_sem", mrb_uv_sem_free
};

static mrb_value
mrb_uv_sem_init(mrb_state *mrb, mrb_value self)
{
  mrb_int v;
  uv_sem_t* s;
  mrb_get_args(mrb, "i", &v);

  s = (uv_sem_t*)mrb_malloc(mrb, sizeof(uv_sem_t));
  mrb_uv_check_error(mrb, uv_sem_init(s, v));
  DATA_TYPE(self) = &sem_type;
  DATA_PTR(self) = s;
  return self;
}

static mrb_value
mrb_uv_sem_destroy(mrb_state *mrb, mrb_value self)
{
  uv_sem_t *sem = (uv_sem_t*)mrb_uv_get_ptr(mrb, self, &sem_type);
  uv_sem_destroy(sem);
  mrb_free(mrb, DATA_PTR(self));
  DATA_PTR(self) = NULL;
  return self;
}

static mrb_value
mrb_uv_sem_post(mrb_state *mrb, mrb_value self)
{
  uv_sem_t *sem = (uv_sem_t*)mrb_uv_get_ptr(mrb, self, &sem_type);
  return uv_sem_post(sem), self;
}

static mrb_value
mrb_uv_sem_wait(mrb_state *mrb, mrb_value self)
{
  uv_sem_t *sem = (uv_sem_t*)mrb_uv_get_ptr(mrb, self, &sem_type);
  return uv_sem_wait(sem), self;
}

static mrb_value
mrb_uv_sem_trywait(mrb_state *mrb, mrb_value self)
{
  int err;
  uv_sem_t *sem = (uv_sem_t*)mrb_uv_get_ptr(mrb, self, &sem_type);
  err = uv_sem_trywait(sem);
  if(err == UV_EAGAIN) {
    return mrb_false_value();
  }
  if(err < 0) {
    mrb_uv_check_error(mrb, err);
  }
  return mrb_true_value();
}

static mrb_value
mrb_uv_sem_destroyed(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(DATA_PTR(self) == NULL);
}

static struct {
  uv_mutex_t lock;
  mrb_state *mrb;
  mrb_value block;
} once_info;

static void
_uv_once_cb() {
  mrb_assert(!mrb_nil_p(once_info.block));
  mrb_yield_argv(once_info.mrb, once_info.block, 0, NULL);
}

static void
mrb_uv_once_free(mrb_state *mrb, void *p)
{
  mrb_assert(p);
  mrb_free(mrb, p);
}

static struct mrb_data_type const mrb_uv_once_type = {
  "uv_once", mrb_uv_once_free
};

static mrb_value
mrb_uv_once_init(mrb_state *mrb, mrb_value self)
{
  uv_once_t *once;
  mrb_value b;
  static uv_once_t const initial_once = UV_ONCE_INIT;

  mrb_get_args(mrb, "&", &b);

  if (mrb_nil_p(b)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "block not passed to UV::Once initialization");
  }

  once = (uv_once_t*)mrb_malloc(mrb, sizeof(uv_once_t));
  *once = initial_once;
  DATA_PTR(self) = once;
  DATA_TYPE(self) = &mrb_uv_once_type;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "once_cb"), b);
  return self;
}

static mrb_value
mrb_uv_once(mrb_state *mrb, mrb_value self)
{
  uv_mutex_lock(&once_info.lock);

  once_info.mrb = mrb;
  once_info.block = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "once_cb"));
  uv_once((uv_once_t*)DATA_PTR(self), _uv_once_cb);

  uv_mutex_unlock(&once_info.lock);
  return self;
}

static void
mrb_uv_rwlock_free(mrb_state *mrb, void *p)
{
  if (p) {
    uv_rwlock_destroy((uv_rwlock_t*)p);
    mrb_free(mrb, p);
  }
}

static struct mrb_data_type const mrb_uv_rwlock_type = {
  "uv_rwlock", mrb_uv_rwlock_free
};

static mrb_value
mrb_uv_rwlock_init(mrb_state *mrb, mrb_value self)
{
  int err;
  uv_rwlock_t *rwlock;

  rwlock = (uv_rwlock_t*)mrb_malloc(mrb, sizeof(uv_rwlock_t));
  err = uv_rwlock_init(rwlock);
  if (err < 0) {
    mrb_free(mrb, rwlock);
    mrb_uv_check_error(mrb, err);
  }
  DATA_PTR(self) = rwlock;
  DATA_TYPE(self) = &mrb_uv_rwlock_type;
  return self;
}

static mrb_value
mrb_uv_rwlock_destroy(mrb_state *mrb, mrb_value self)
{
  uv_rwlock_destroy((uv_rwlock_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_rwlock_type));
  DATA_PTR(self) = NULL;
  return self;
}
#define define_lock(s, n)                                               \
  static mrb_value                                                      \
  mrb_uv_rwlock_ ## n ## _lock(mrb_state *mrb, mrb_value self)          \
  {                                                                     \
    uv_rwlock_t *lock = (uv_rwlock_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_rwlock_type); \
    return uv_rwlock_ ## s ## lock(lock), self;                         \
  }                                                                     \
                                                                        \
  static mrb_value                                                      \
  mrb_uv_rwlock_try_ ## n ## _lock(mrb_state *mrb, mrb_value self)      \
  {                                                                     \
    int err;                                                            \
    err = uv_rwlock_try ## s ## lock((uv_rwlock_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_rwlock_type)); \
      switch(err) {                                                     \
      case UV_EAGAIN: return symbol_value_lit(mrb, "again");            \
      case UV_EBUSY: return symbol_value_lit(mrb, "busy");              \
      default:                                                          \
        mrb_uv_check_error(mrb, err);                                   \
        return self;                                                    \
      }                                                                 \
  }                                                                     \
                                                                        \
  static mrb_value                                                      \
  mrb_uv_rwlock_ ## n ## _unlock(mrb_state *mrb, mrb_value self)        \
  {                                                                     \
    uv_rwlock_t *lock = (uv_rwlock_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_rwlock_type); \
    return uv_rwlock_ ## s ## unlock(lock), self;                       \
  }                                                                     \

define_lock(wr, write)
define_lock(rd, read)

#undef define_lock

static void
mrb_uv_cond_free(mrb_state *mrb, void* p)
{
  if (p) {
    uv_cond_destroy((uv_cond_t*)p);
    mrb_free(mrb, p);
  }
}

static struct mrb_data_type const mrb_uv_cond_type = {
  "uv_cond", mrb_uv_cond_free
};

static mrb_value
mrb_uv_cond_init(mrb_state *mrb, mrb_value self)
{
  int err;
  uv_cond_t *cond;

  cond = (uv_cond_t*)mrb_malloc(mrb, sizeof(uv_cond_t));
  err = uv_cond_init(cond);
  if (err < 0) {
    mrb_free(mrb, cond);
    mrb_uv_check_error(mrb, err);
  }

  DATA_PTR(self) = cond;
  DATA_TYPE(self) = &mrb_uv_cond_type;
  return self;
}

static mrb_value
mrb_uv_cond_destroy(mrb_state *mrb, mrb_value self)
{
  uv_cond_destroy((uv_cond_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_cond_type));
  DATA_PTR(self) = NULL;
  return self;
}

static mrb_value
mrb_uv_cond_signal(mrb_state *mrb, mrb_value self)
{
  return uv_cond_signal((uv_cond_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_cond_type)), self;
}

static mrb_value
mrb_uv_cond_broadcast(mrb_state *mrb, mrb_value self)
{
  return uv_cond_broadcast((uv_cond_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_cond_type)), self;
}

static mrb_value
mrb_uv_cond_wait(mrb_state *mrb, mrb_value self)
{
  mrb_value mutex_val;
  uv_mutex_t *mutex;
  mrb_get_args(mrb, "o", &mutex_val);

  mutex = (uv_mutex_t*)mrb_uv_get_ptr(mrb, mutex_val, &mrb_uv_mutex_type);
  return uv_cond_wait((uv_cond_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_cond_type), mutex), self;
}

static mrb_value
mrb_uv_cond_timed_wait(mrb_state *mrb, mrb_value self)
{
  mrb_value mutex_val;
  mrb_int timeout;
  uv_mutex_t *mutex;
  int err;
  mrb_get_args(mrb, "oi", &mutex_val, &timeout);

  mutex = (uv_mutex_t*)mrb_uv_get_ptr(mrb, mutex_val, &mrb_uv_mutex_type);
  err = uv_cond_timedwait((uv_cond_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_cond_type), mutex, timeout);
  if (err == UV_ETIMEDOUT) {
    return symbol_value_lit(mrb, "timedout");
  }
  mrb_uv_check_error(mrb, err);
  return self;
}

static void
mrb_uv_key_free(mrb_state *mrb, void* p)
{
  if (p) {
    uv_key_delete((uv_key_t*)p);
    mrb_free(mrb, p);
  }
}

static struct mrb_data_type const mrb_uv_key_type = {
  "uv_key", mrb_uv_key_free
};

static mrb_value
mrb_uv_key_init(mrb_state *mrb, mrb_value self)
{
  uv_key_t *key;
  int err;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "values"), mrb_ary_new(mrb));

  key = (uv_key_t*)mrb_malloc(mrb, sizeof(uv_key_t));
  err = uv_key_create(key);
  if (err < 0) {
    mrb_free(mrb, key);
    mrb_uv_check_error(mrb, err);
  }
  DATA_PTR(self) = key;
  DATA_TYPE(self) = &mrb_uv_key_type;
  return self;
}

static mrb_value
mrb_uv_key_destroy(mrb_state *mrb, mrb_value self)
{
  uv_key_t *key = (uv_key_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_key_type);
  mrb_ary_clear(mrb, mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "values")));
  uv_key_delete(key);
  return self;
}

static mrb_value
mrb_uv_key_get(mrb_state *mrb, mrb_value self)
{
  uv_key_t *key;
  void *p;

  key = (uv_key_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_key_type);
  p = uv_key_get(key);
  return p? mrb_obj_value(p) : mrb_nil_value();
}

static mrb_value
mrb_uv_key_set(mrb_state *mrb, mrb_value self)
{
  uv_key_t *key;
  void *p;
  mrb_value new_val;
  mrb_value ary;

  mrb_get_args(mrb, "o", &new_val);

  if (mrb_type(new_val) < MRB_TT_HAS_BASIC) {
    mrb_raisef(mrb, E_TYPE_ERROR, "cannot store value without basic: %S", new_val);
  }

  key = (uv_key_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_key_type);
  p = uv_key_get(key);

  ary = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "values"));
  mrb_assert(mrb_array_p(ary));

  if (p) {
    /* remove value */
    int i, dst;
    for (i = 0, dst = 0; i < RARRAY_LEN(ary); ++i) {
      mrb_value v = RARRAY_PTR(ary)[i];
      if (mrb_ptr(v) != p) {
        mrb_ary_ptr(ary)->ptr[dst++] = v;
      }
    }
    RARRAY_LEN(ary) = dst;
  }

  uv_key_set(key, mrb_ptr(new_val));
  mrb_ary_push(mrb, ary, new_val); /* protect from GC */

  return new_val;
}

void mrb_mruby_uv_gem_init_thread(mrb_state *mrb, struct RClass *UV)
{
  struct RClass* _class_uv_thread;
  struct RClass* _class_uv_barrier;
  struct RClass* _class_uv_semaphore;
  struct RClass* _class_uv_mutex;
  struct RClass* _class_uv_once;
  struct RClass* _class_uv_rwlock;
  struct RClass* _class_uv_cond;
  struct RClass* _class_uv_key;
  int const ai = mrb_gc_arena_save(mrb);

  mrb_define_module_function(mrb, UV, "thread_self", mrb_uv_thread_self, MRB_ARGS_NONE());

  _class_uv_thread = mrb_define_class_under(mrb, UV, "Thread", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_thread, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_thread, "initialize", mrb_uv_thread_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_thread, "join", mrb_uv_thread_join, MRB_ARGS_NONE());
  mrb_define_method(mrb, UV, "==", mrb_uv_thread_eq, MRB_ARGS_REQ(1));
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_barrier = mrb_define_class_under(mrb, UV, "Barrier", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_barrier, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_barrier, "initialize", mrb_uv_barrier_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "wait", mrb_uv_barrier_wait, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "destroy", mrb_uv_barrier_destroy, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_semaphore = mrb_define_class_under(mrb, UV, "Semaphore", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_semaphore, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_semaphore, "initialize", mrb_uv_sem_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_semaphore, "destroy", mrb_uv_sem_destroy, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_semaphore, "post", mrb_uv_sem_post, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_semaphore, "wait", mrb_uv_sem_wait, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_semaphore, "try_wait", mrb_uv_sem_trywait, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_semaphore, "destroyed?", mrb_uv_sem_destroyed, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_mutex = mrb_define_class_under(mrb, UV, "Mutex", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_mutex, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_mutex, "initialize", mrb_uv_mutex_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "lock", mrb_uv_mutex_lock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "trylock", mrb_uv_mutex_trylock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "unlock", mrb_uv_mutex_unlock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "destroy", mrb_uv_mutex_destroy, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_once = mrb_define_class_under(mrb, UV, "Once", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_once, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_once, "initialize", mrb_uv_once_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_once, "run", mrb_uv_once, MRB_ARGS_NONE());
  mrb_uv_check_error(mrb, uv_mutex_init(&once_info.lock));
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_rwlock = mrb_define_class_under(mrb, UV, "RWLock", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_rwlock, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_rwlock, "initialize", mrb_uv_rwlock_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "destroy", mrb_uv_rwlock_destroy, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "read_lock", mrb_uv_rwlock_read_lock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "try_read_lock", mrb_uv_rwlock_try_read_lock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "read_unlock", mrb_uv_rwlock_read_unlock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "write_lock", mrb_uv_rwlock_write_lock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "try_write_lock", mrb_uv_rwlock_try_write_lock, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_rwlock, "write_unlock", mrb_uv_rwlock_write_unlock, MRB_ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_cond = mrb_define_class_under(mrb, UV, "Cond", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_cond, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_cond, "initialize", mrb_uv_cond_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_cond, "destroy", mrb_uv_cond_destroy, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_cond, "signal", mrb_uv_cond_signal, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_cond, "broadcast", mrb_uv_cond_broadcast, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_cond, "wait", mrb_uv_cond_wait, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _class_uv_cond, "timed_wait", mrb_uv_cond_timed_wait, MRB_ARGS_REQ(1));
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_key = mrb_define_class_under(mrb, UV, "Key", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_key, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_key, "initialize", mrb_uv_key_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_key, "destroy", mrb_uv_key_destroy, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_key, "get", mrb_uv_key_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, _class_uv_key, "set", mrb_uv_key_set, MRB_ARGS_REQ(1));
  mrb_gc_arena_restore(mrb, ai);
}
