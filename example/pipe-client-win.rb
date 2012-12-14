c = UV::Pipe.new()
c.connect('\\\\.\\pipe\\mruby-uv') {|x|
  if x == 0
    c.read_start {|b|
      puts b.to_s
    }
  else
    c.close()
  end
}
UV::run()
