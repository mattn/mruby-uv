#!mruby

UV::FS::readdir(".") do |x,a|
  puts a
end
UV::run()
