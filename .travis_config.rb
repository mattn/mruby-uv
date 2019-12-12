MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  enable_test

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem :core => 'mruby-time'
  gem "#{MRUBY_ROOT}/.." do |c|
    c.bundle_uv
  end
end

MRuby::Build.new('libuv-v1.0.0') do |conf|
  toolchain :gcc
  enable_debug
  enable_test

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem :core => 'mruby-time'
  ENV['SKIP_UV_BUNDLE'] = '1'
  gem "#{MRUBY_ROOT}/.." do |c|
    c.bundle_uv '1.0.0'
  end
end
