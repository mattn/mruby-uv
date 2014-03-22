#!mruby
begin; require 'mruby-uv'; rescue Error; end

t = UV::Timer.new

if UV::Signal.const_defined?(:SIGPIPE)
  UV::Signal.new.start(UV::Signal::SIGPIPE) do
    puts "connection closed"
    t.stop
  end
end

s = UV::TCP.new
s.bind(UV::ip4_addr('127.0.0.1', 8888))
puts "bound to #{s.getsockname}"
s.listen(5) {|x|
  return if x != 0
  c = s.accept
  puts "connected (peer: #{c.getpeername})"
  c.write "helloworld\r\n"
  t.start(1000, 1000) {|x|
    puts "helloworld\n"
    begin
      c.write "helloworld\r\n"
    rescue RuntimeError
      puts "disconnected"
      c.close
      c = nil
      t.stop
      t = nil
    end
  }
}

UV::run()
