#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <variable.h>
#include <mrb_uv.h>

#define _(...) #__VA_ARGS__ "\n"

int
main()
{
  int n;
  mrb_state* mrb;
  struct mrb_parser_state* st;
  char* code =
_( require 'UV'                              )
_( addr = UV::Ip4Addr.new('127.0.0.1', 80)   )
_( tcp = UV::TCP.new()                       )
_( tcp.connect(addr) {|x|                    )
_(   tcp.read_start {|b|                     )
_(     p b.to_s                              )
_(   }                                       )
_( }                                         )
_( UV.run()                                  );

  mrb = mrb_open();
  mrb_uv_init(mrb);
  st = mrb_parse_string(mrb, code);
  n = mrb_generate_code(mrb, st->tree);
  mrb_pool_close(st->pool);
  mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());
  return 0;
}
