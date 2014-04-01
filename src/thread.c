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
  int err = uv_mutex_init(m);
  if (err < 0) {
    mrb_uv_error(mrb, err);
  }
  DATA_PTR(self) = m;
  DATA_TYPE(self) = &mrb_uv_mutex_type;
  return self;
}

static mrb_value
mrb_uv_mutex_lock(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type);
  uv_mutex_lock(m);
  return mrb_nil_value();
}

static mrb_value
mrb_uv_mutex_unlock(mrb_state *mrb, mrb_value self)
{
  uv_mutex_t *m = (uv_mutex_t*)mrb_uv_get_ptr(mrb, self, &mrb_uv_mutex_type);
  uv_mutex_unlock(m);
  return mrb_nil_value();
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
  return mrb_nil_value();
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
  int err;
  mrb_value thread_arg = mrb_nil_value();
  mrb_value b = mrb_nil_value();
  mrb_uv_thread* context = NULL;

  mrb_get_args(mrb, "&|o", &b, &thread_arg);

  context = (mrb_uv_thread*)mrb_malloc(mrb, sizeof(mrb_uv_thread));
  context->instance = self;

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "thread_proc"), b);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "thread_arg"), thread_arg);
  DATA_PTR(self) = context;
  DATA_TYPE(self) = &mrb_uv_thread_type;

  err = uv_thread_create(&context->thread, _uv_thread_proc, context);
  if (err != 0) {
    mrb_uv_error(mrb, err);
  }
  return self;
}

static mrb_value
mrb_uv_thread_join(mrb_state *mrb, mrb_value self)
{
  mrb_uv_thread* context = NULL;

  Data_Get_Struct(mrb, self, &mrb_uv_thread_type, context);

  uv_thread_join(&context->thread);
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
  int err;
  mrb_int arg_count;
  uv_barrier_t* context = NULL;

  mrb_get_args(mrb, "i", &arg_count);

  context = (uv_barrier_t*)mrb_malloc(mrb, sizeof(uv_barrier_t));

  err = uv_barrier_init(context, arg_count);
  if (err != 0) {
    mrb_uv_error(mrb, err);
  }
  DATA_PTR(self) = context;
  DATA_TYPE(self) = &barrier_type;
  return self;
}

static mrb_value
mrb_uv_barrier_wait(mrb_state *mrb, mrb_value self)
{
  uv_barrier_wait((uv_barrier_t*)mrb_uv_get_ptr(mrb, self, &barrier_type));
  return mrb_nil_value();
}

static mrb_value
mrb_uv_barrier_destroy(mrb_state *mrb, mrb_value self)
{
  uv_barrier_destroy((uv_barrier_t*)mrb_uv_get_ptr(mrb, self, &barrier_type));
  mrb_free(mrb, DATA_PTR(self));
  DATA_PTR(self) = NULL;
  return mrb_nil_value();
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
  int err;
  mrb_get_args(mrb, "i", &v);

  s = (uv_sem_t*)mrb_malloc(mrb, sizeof(uv_sem_t));
  if((err = uv_sem_init(s, v)) < 0) {
    mrb_free(mrb, s);
    mrb_uv_error(mrb, err);
  }

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
    mrb_uv_error(mrb, err);
  }
  return mrb_true_value();
}

static mrb_value
mrb_uv_sem_destroyed(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(DATA_PTR(self) == NULL);
}

void mrb_mruby_uv_gem_init_thread(mrb_state *mrb, struct RClass *UV)
{
  struct RClass* _class_uv_thread;
  struct RClass* _class_uv_barrier;
  struct RClass* _class_uv_semaphore;
  struct RClass* _class_uv_mutex;
  int const ai = mrb_gc_arena_save(mrb);

  _class_uv_thread = mrb_define_class_under(mrb, UV, "Thread", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_thread, MRB_TT_DATA);
  mrb_define_module_function(mrb, _class_uv_thread, "self", mrb_uv_thread_self, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_thread, "initialize", mrb_uv_thread_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_thread, "join", mrb_uv_thread_join, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);

  _class_uv_barrier = mrb_define_class_under(mrb, UV, "Barrier", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_uv_barrier, MRB_TT_DATA);
  mrb_define_method(mrb, _class_uv_barrier, "initialize", mrb_uv_barrier_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "wait", mrb_uv_barrier_wait, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_barrier, "destroy", mrb_uv_barrier_destroy, ARGS_NONE());
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
  mrb_define_method(mrb, _class_uv_mutex, "initialize", mrb_uv_mutex_init, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "lock", mrb_uv_mutex_lock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "trylock", mrb_uv_mutex_trylock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "unlock", mrb_uv_mutex_unlock, ARGS_NONE());
  mrb_define_method(mrb, _class_uv_mutex, "destroy", mrb_uv_mutex_destroy, ARGS_NONE());
  mrb_gc_arena_restore(mrb, ai);
}
