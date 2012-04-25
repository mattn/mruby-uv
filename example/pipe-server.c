#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <mrb_uv.h>

#define _(...) #__VA_ARGS__ "\n"

int
main()
{
  int n;
  mrb_state* mrb;
  struct mrb_parser_state* st;
  char* code =
 _(
)_( require 'UV'
)_(
)_( s = UV::Pipe.new()
)_( s.bind('/tmp/mruby-uv')
)_( s.listen(5) {|x|
)_(   return if x != 0
)_(   c = s.accept()
)_(   puts "connected"
)_(   t = UV::Timer.new()
)_(   t.start(1000, 1000) {|x|
)_(     puts "helloworld\n"
)_(     c.write "helloworld\r\n"
)_(   }
)_( }
)_( UV.run()
);

  mrb = mrb_open();
  mrb_uv_init(mrb);
  st = mrb_parse_string(mrb, code);
  n = mrb_generate_code(mrb, st->tree);
  mrb_pool_close(st->pool);
  mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());
  return 0;
}
