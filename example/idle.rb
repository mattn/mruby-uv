i = UV::Idle.new()
i.start {|x|
  puts "idle"
}
UV::run()
