#!mruby
begin; require 'mruby-uv'; rescue Exception; end

r = UV::UDP.new()
r.bind6(UV::ip6_addr('::1', 8888))
r.recv_start {|data, addr, flags|
  if data && data.size > 0
    puts data
  end
}
UV::run()
