#!mruby
begin; require 'mruby-uv'; rescue Exception; end

l = UV::Loop.new()
t = UV::Timer.new(l)
i = 3
t.start(1000, 1000) {|x|
  puts i
  i -= 1
  if i < 0
    t.close()
  end
}
l.run()
