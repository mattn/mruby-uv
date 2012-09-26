i = UV::Idle.new()
i.start {|i, x|
  puts "idle"
}
UV::run()
