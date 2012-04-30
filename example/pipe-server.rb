require 'UV'

s = UV::Pipe.new()
s.bind('/tmp/mruby-uv')
s.listen(5) {|x|
  return if x != 0
  c = s.accept()
  puts "connected"
  t = UV::Timer.new()
  t.start(1000, 1000) {|x|
    puts "helloworld\n"
    c.write "helloworld\r\n"
  }
}
UV::run()
