#!mruby
begin; require 'mruby-uv'; rescue Exception; end

t = UV::Timer.new()

a = UV::Async.new {|x|
  puts "async!"
}

p = UV::Prepare.new()
p.start {|x|
  t.start(1000, 1000) {|x|
    a.send
  }
}

UV::run()
