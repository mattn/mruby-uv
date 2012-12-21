#!mruby

s = UV::Signal.new()
s.start(UV::Signal::SIGINT) do |x|
  puts "SIGINT"
end

UV::run()
