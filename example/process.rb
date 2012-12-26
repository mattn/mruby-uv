#!mruby

ps = UV::Process.new({
  'file' => 'c:\\windows\\system32\\notepad.exe',
  'args' => []
})

ps.spawn do |sig|
  puts "exit #{sig}"
end

t = UV::Timer.new
t.start(3000, 0) do |x|
  ps.kill(UV::Signal::SIGINT)
end

UV::run()
