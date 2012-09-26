r = UV::UDP.new()
r.bind(UV::ip4_addr('127.0.0.1', 8888))
r.recv_start {|r, data, addr, flags|
  if data.size > 0
    puts data
  end
}
UV::run()
