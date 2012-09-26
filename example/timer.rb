t = UV::Timer.new()
c = 3
t.start(1000, 1000) {|t, x|
  puts c
  c -= 1
  if c < 0
    t.close()
    t.stop()
  end
}
UV::run()
