#!mruby
begin; require 'mruby-uv'; rescue Error; end

UV::FS::readdir(".", 0) do |x,a|
  puts a
end
UV::run()
