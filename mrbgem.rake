MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'

  if ENV['OS'] == 'Windows_NT'
    spec.linker.libraries << ['psapi', 'iphlpapi', 'ws2_32', 'uv']
  else
    if ENV['libuv_path'] != nil
      spec.linker.flags << "-L" + ENV['libuv_path']
      spec.cc.flags << '-I"#{ENV["libuv_path"] + "/include"}"'
    end
    spec.linker.libraries << ['uv', 'rt', 'm']
  end
end
