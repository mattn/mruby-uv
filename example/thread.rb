thread = UV::Thread.new(123) {|x|
  puts "foo#{x}"
}
thread.join
