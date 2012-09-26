c = UV::Pipe.new()
c.connect('\\\\.\\pipe\\mruby-uv') {|c, x|
  if x == 0
    c.read_start {|c, b|
      puts b.to_s
    }
  else
    c.close()
  end
}
UV::run()
