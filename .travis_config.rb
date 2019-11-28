MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  enable_test

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem :core => 'mruby-time'
  gem "#{MRUBY_ROOT}/.." do |c|
    c.bundle_onigmo
  end
end

MRuby::Build.new('libuv-v1.0.0') do |conf|
  toolchain :gcc
  enable_debug
  enable_test

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem :core => 'mruby-time'
  gem "#{MRUBY_ROOT}/.." do |c|
    c.bundle_onigmo '1.0.0'
  end
end
