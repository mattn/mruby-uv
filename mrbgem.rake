MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'

  if ENV['OS'] == 'Windows_NT'
    spec.mruby_libs = '-luv -lws2_32 -liphlpapi -lpsapi'
  else
    spec.mruby_libs = '-luv -lrt -lm'
  end
end
