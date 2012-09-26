c = UV::Pipe.new()
c.connect('/tmp/mrub-yuv') {|c, x|
  if x == 0
    c.read_start {|b|
      p b.to_s
    }
  else
    c.close()
  end
}
UV::run()
