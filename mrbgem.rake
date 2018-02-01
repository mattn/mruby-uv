MRuby::Gem::Specification.new('mruby-uv') do |spec|
  spec.license = 'MIT'
  spec.authors = 'mattn'
  spec.summary = 'libuv mruby binding'
  spec.add_dependency 'mruby-time',       core: 'mruby-time'
  spec.add_dependency 'mruby-sprintf',    core: 'mruby-sprintf'
  spec.add_dependency 'mruby-fiber',      core: 'mruby-fiber'
  spec.add_dependency 'mruby-string-ext', core: 'mruby-string-ext'

  def self.run_command(env, command)
    fail "#{command} failed" unless system(env, command)
  end

  def cross?; build.kind_of? MRuby::CrossBuild end

  def self.bundle_uv
    visualcpp = ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']

    version = '1.19.1'
    libuv_dir = "#{build_dir}/libuv-#{version}"
    libuv_lib = libfile "#{libuv_dir}/.libs/libuv"
    header = "#{libuv_dir}/include/uv.h"
    objext = visualcpp ? '.obj' : '.o'
    libmruby_a = libfile("#{build.build_dir}/lib/libmruby")
    libuv_objs_dir = "#{libuv_dir}/libuv_objs"

    task :clean do
      FileUtils.rm_rf [libuv_dir, "#{libuv_dir}.tar.gz"]
    end

    file header do |t|
      begin
        FileUtils.mkdir_p build_dir
        Dir.chdir(build_dir) do
          _pp 'getting', "libuv-#{version}"
          run_command({}, "curl -L -o libuv-#{version}.tar.gz https://github.com/libuv/libuv/archive/v#{version}.tar.gz")
          _pp 'extracting', "libuv-#{version}"
          run_command({}, "tar -zxf libuv-#{version}.tar.gz")
        end
      rescue => e
        p e
        FileUtils.rm_f "libuv-#{version}.tar.gz"
        FileUtils.rm_rf "libuv-#{version}"
        raise e
      end
    end

    file libuv_lib => header do |t|
      Dir.chdir(libuv_dir) do
        e = {
          'CC'  => "#{build.cc.command} #{build.cc.flags.join(' ')} -DNDEBUG",
          'CXX' => "#{build.cxx.command} #{build.cxx.flags.join(' ')}",
          'LD'  => "#{build.linker.command} #{build.linker.flags.join(' ')}",
          'AR'  => build.archiver.command
        }
        _pp 'autotools', libuv_dir
        configure_opts = %w(--disable-shared --enable-static)
        if cross? && build.host_target && build.build_target
          configure_opts += ["--host #{build.host_target}", "--build #{build.build_target}"]
          e['LD'] = "x86_64-w64-mingw32-ld #{build.linker.flags.join(' ')}" if build.host_target == 'x86_64-w64-mingw32'
          e['LD'] = "i686-w64-mingw32-ld #{build.linker.flags.join(' ')}" if build.host_target == 'i686-w64-mingw32'
        end
        run_command e, './autogen.sh' if File.exists? 'autogen.sh'
        run_command e, "./configure #{configure_opts.join(" ")}"
        run_command e, 'make'
      end

      FileUtils.mkdir_p libuv_objs_dir
      Dir.chdir(libuv_objs_dir) do
        unless visualcpp
          `ar x #{libuv_lib}`
        else
          winname = libuv_lib.gsub(%'/', '\\')
          `lib -nologo -list #{winname}`.each_line do |line|
            line.chomp!
            `lib -nologo -extract:#{line} #{winname}`
          end
        end
      end
      file libmruby_a => Dir.glob("#{libuv_objs_dir}/*#{objext}")
    end

    file libmruby_a => Dir.glob("#{libuv_objs_dir}/*#{objext}") if File.exists? libuv_lib

    Dir.glob("#{dir}/src/*.c") { |f| file f => libuv_lib }
    cc.include_paths << "#{libuv_dir}/include"
    linker.library_paths << File.dirname(libuv_lib)
  end

  if (not cross? and ENV['OS'] == 'Windows_NT') || (cross? && spec.build.host_target && spec.build.host_target.include?("mingw32"))
    spec.linker.libraries << ['uv', 'psapi', 'iphlpapi', 'ws2_32']
  elsif (not cross? and `uname`.chomp =~ /darwin|freebsd/i) || (cross? && spec.build.host_target && spec.build.host_target.include?("darwin"))
    spec.linker.libraries << ['uv', 'pthread', 'm']
  else
    spec.linker.libraries << ['uv', 'pthread', 'rt', 'm', 'dl']
  end

  if build.cc.respond_to? :search_header_path
    next if build.cc.search_header_path 'uv.h'
  end
  if ENV['OS'] == 'Windows_NT'
    next
  end

  spec.bundle_uv
end
