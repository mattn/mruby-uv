#!mruby
begin; require 'mruby-uv'; rescue Exception; end

UV::FS::readdir(ARGV[0] || ".", 0) do |x|
  puts x
end
UV::run()
