require 'UV'
c = UV::TCP.new()
c.connect(UV.ip4_addr('127.0.0.1', 8888)) {|x|
  if x == 0
    c.read_start {|b|
      p b.to_s
    }
  else
    c.close()
  end
}
UV.run()
