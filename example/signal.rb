#!mruby
begin; require 'mruby-uv'; rescue Exception; end

s = UV::Signal.new()
s.start(UV::Signal::SIGINT) do |x|
  puts "SIGINT"
end

UV::run()
