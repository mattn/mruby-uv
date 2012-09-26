t = UV::Timer.new()

a = UV::Async.new {|a, x|
  puts "async!"
}

p = UV::Prepare.new()
p.start {|p, x|
  t.start(1000, 1000) {|t, x|
    a.send
  }
}

UV::run()
