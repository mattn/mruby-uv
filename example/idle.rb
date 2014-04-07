#!mruby
begin; require 'mruby-uv'; rescue Exception; end

i = UV::Idle.new()
i.start {|x|
  puts "idle"
}
UV::run()
