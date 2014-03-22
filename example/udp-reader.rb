#!mruby
begin; require 'mruby-uv'; rescue Error; end

r = UV::UDP.new()
r.bind(UV::ip4_addr('127.0.0.1', 8888))
puts "bound to #{r.getsockname}"
r.recv_start {|data, addr, flags|
  if data && data.size > 0
    puts data
  end
}
UV::run()
