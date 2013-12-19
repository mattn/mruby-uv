#!mruby
begin; require 'mruby-uv'; rescue Error; end

s = UV::Signal.new()
s.start(UV::Signal::SIGINT) do |x|
  puts "SIGINT"
end

UV::run()
