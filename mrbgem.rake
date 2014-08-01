MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'
  spec.summary = 'libuv mruby binding'
  spec.add_dependency 'mruby-time'
  spec.add_dependency 'mruby-sprintf'

  is_cross = build.kind_of? MRuby::CrossBuild

  if not is_cross and ENV['OS'] == 'Windows_NT'
    spec.linker.libraries << ['uv', 'psapi', 'iphlpapi', 'ws2_32']
  elsif not is_cross and `uname`.chomp =~ /darwin/i
    spec.linker.libraries << ['uv', 'pthread', 'm']
  else
    spec.linker.libraries << ['uv', 'pthread', 'rt', 'm', 'dl']
  end

  if build.cc.respond_to? :search_header_path
    next if build.cc.search_header_path 'uv.h'
  elsif ENV['OS'] == 'Windows_NT'
    next
  end

  require 'open3'

  version = '0.11.27'
  libuv_dir = "#{build_dir}/libuv-#{version}"
  libuv_lib = libfile "#{libuv_dir}/.libs/libuv"
  header = "#{libuv_dir}/include/uv.h"

  task :clean do
    FileUtils.rm_rf [libuv_dir, "#{libuv_dir}.tar.gz"]
  end

  file header do |t|
    FileUtils.mkdir_p libuv_dir

    _pp 'getting', "libuv-v#{version}"
    begin
      FileUtils.mkdir_p build_dir
      Dir.chdir(build_dir) do
        File.open("libuv-v#{version}.tar.gz", 'w') do |f|
          IO.popen("curl -L \"https://github.com/joyent/libuv/archive/v#{version}.tar.gz\"") do |io|
            f.write io.read
          end
          raise IOError unless $?.exitstatus
        end

        _pp 'extracting', "libuv-v#{version}"
        `tar -zxf libuv-v#{version}.tar.gz`
        raise IOError unless $?.exitstatus
      end
    rescue IOError
      File.delete "libuv-v#{version}.tar.gz"
      exit(-1)
    end
  end

  def run_command(env, command)
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  file libuv_lib => header do |t|
    Dir.chdir(libuv_dir) do
      e = {
        'CC' => spec.build.cc.command,
        'CXX' => spec.build.cxx.command,
        'LD' => spec.build.linker.command,
        'AR' => spec.build.archiver.command }
      _pp 'autotools', libuv_dir
      run_command e, './autogen.sh' if File.exists? 'autogen.sh'
      run_command e, './configure --disable-shared --enable-static'
      run_command e, 'make'
    end
  end

  Dir.glob("#{dir}/src/*.c") { |f| file f => libuv_lib }
  spec.cc.include_paths << "#{libuv_dir}/include"
  spec.linker.library_paths << File.dirname(libuv_lib)
end
