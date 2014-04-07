#!mruby
begin; require 'mruby-uv'; rescue Exception; end

t = UV::Timer.new()
c = 3
t.start(1000, 1000) {|x|
  puts c
  c -= 1
  if c < 0
    t.stop()
  end
}
UV::run()
