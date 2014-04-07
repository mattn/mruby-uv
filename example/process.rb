#!mruby
begin; require 'mruby-uv'; rescue Exception; end

if UV::IS_WINDOWS == true
  ps = UV::Process.new({
    'file' => 'cmd',
    'args' => ['/c', 'dir /S ..']
  })
else
  ps = UV::Process.new({
    'file' => 'find',
    'args' => ['../..']
  })
end
ps.stdout_pipe = UV::Pipe.new(0)

ps.spawn do |sig|
  puts "exit #{sig}"
end
ps.stdout_pipe.read_start do |b|
  puts b
end

t = UV::Timer.new
t.start(1000, 0) do |x|
  ps.kill(UV::Signal::SIGINT)
end

UV::run()
