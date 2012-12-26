#!mruby

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
pipe = UV::Pipe.new(0)
ps.stdout_pipe = pipe

ps.spawn do |sig|
  puts "exit #{sig}"
end
pipe.read_start do |b|
  puts b
end

t = UV::Timer.new
t.start(1000, 0) do |x|
  ps.kill(UV::Signal::SIGINT)
end

UV::run()
