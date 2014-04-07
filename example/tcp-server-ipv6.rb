#!mruby
begin; require 'mruby-uv'; rescue Exception; end

t = UV::Timer.new

if UV::Signal.const_defined?(:SIGPIPE)
  UV::Signal.new.start(UV::Signal::SIGPIPE) do
    puts "connection closed"
    t.stop
  end
end

s = UV::TCP.new
s.bind6(UV::ip6_addr('::1', 8888))
s.listen(5) {|x|
  return if x != 0
  c = s.accept
  puts "connected"
  c.write "helloworld\r\n"
  t.start(1000, 1000) {|x|
    puts "helloworld\n"
    begin
      c.write "helloworld\r\n"
    rescue UVError
      puts "disconnected"
      c.close
      c = nil
      t.stop
      t = nil
    end
  }
}

UV::run()
