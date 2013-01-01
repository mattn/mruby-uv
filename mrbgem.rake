MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'
 
  # spec.cflags = ''
 
  # spec.mruby_cflags = ''
  # spec.mruby_ldflags = ''
  if ENV['OS'] == 'Windows_NT'
    spec.mruby_libs = '-luv -lws2_32 -liphlpapi -lpsapi'
  else
    spec.mruby_libs = '-luv -lrt -lm'
  end
 
  spec.rbfiles = Dir.glob("#{dir}/mrblib/*.rb")
  spec.objs = Dir.glob("#{dir}/src/*.{c,cpp,m,asm,S}").map{|f| f.ext('o')}

  spec.test_rbfiles = Dir.glob("#{dir}/test/*.rb")
  spec.test_objs = Dir.glob("#{dir}/test/*.{c,cpp,m,asm,S}").map{|f| f.ext('o')}

  # spec.generated_files = "#{dir}/generated.c"
end
