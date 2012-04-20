#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <variable.h>
#include <mrb_uv.h>

int
main()
{
  int n;
  mrb_state* mrb;
  struct mrb_parser_state* st;
  char* code =
"require 'UV'             \n"
"t = UV::Timer.new()      \n"
"t.start(1000, 1000) {|x| \n"
"  p x                    \n"
"}                        \n"
"p UV.run()               \n";

  mrb = mrb_open();
  mrb_uv_init(mrb);
  st = mrb_parse_string(mrb, code);
  n = mrb_generate_code(mrb, st->tree);
  mrb_pool_close(st->pool);
  mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());
}

