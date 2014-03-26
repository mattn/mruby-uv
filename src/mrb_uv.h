#ifndef MRB_UV_H
#define MRB_UV_H

#include <uv.h>

#include <mruby.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/class.h>
#include <mruby/variable.h>

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

extern const struct mrb_data_type mrb_uv_context_type;
extern const struct mrb_data_type mrb_uv_ip4addr_type;
extern const struct mrb_data_type mrb_uv_ip6addr_type;
extern const struct mrb_data_type mrb_uv_ip4addr_nofree_type;
extern const struct mrb_data_type mrb_uv_ip6addr_nofree_type;

void mrb_mruby_uv_gem_init_handle(mrb_state *mrb, struct RClass *UV);

mrb_uv_context* mrb_uv_context_alloc(mrb_state* mrb);

mrb_value mrb_uv_data_get(mrb_state *mrb, mrb_value self);
mrb_value mrb_uv_data_set(mrb_state *mrb, mrb_value self);

#endif
