#!mruby
begin; require 'mruby-uv'; rescue Error; end

i = UV::Idle.new()
i.start {|x|
  puts "idle"
}
UV::run()
