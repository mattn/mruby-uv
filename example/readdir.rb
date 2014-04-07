#!mruby
begin; require 'mruby-uv'; rescue Exception; end

UV::FS::readdir(".", 0) do |x,a|
  puts a
end
UV::run()
