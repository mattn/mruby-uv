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
 _( require 'UV'
)_( l = UV::Loop.new()
)_( t = UV::Timer.new(l)
)_( i = 3
)_( t.start(1000, 1000) {|x|
)_(   p i
)_(   i -= 1
)_(   if i < 0
)_(     t.close()
)_(   end
)_( }
)_( l.run()
);

  mrb = mrb_open();
  mrb_uv_init(mrb);
  st = mrb_parse_string(mrb, code);
  n = mrb_generate_code(mrb, st->tree);
  mrb_pool_close(st->pool);
  mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());
  return 0;
}
