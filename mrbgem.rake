MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'

  if ENV['OS'] == 'Windows_NT'
    spec.mruby_libs = '-luv -lws2_32 -liphlpapi -lpsapi'
  else
    if ENV['libuv_path'] != nil
      spec.mruby_libs = "-L" + ENV['libuv_path']
      spec.mruby_includes = ENV['libuv_path'] + "/include"
    end
    spec.mruby_libs = "-luv -lrt -lm"
  end
end
