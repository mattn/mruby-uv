UV_INTERVAL = 5

def remove_uv_test_tmpfile
  UV::FS.unlink(UV::IS_WINDOWS ? '\\\\.\\pipe\\mruby-uv' : '/tmp/mruby-uv') rescue nil
  UV::FS.unlink 'foo-bar/bar.txt' rescue nil
  UV::FS.unlink 'foo-bar/foo.txt' rescue nil
  UV::FS.rmdir 'foo-bar/dir' rescue nil
  UV::FS.rmdir 'foo-bar' rescue nil
end

def assert_uv(name, &block)
  assert name do
    block.call
    UV.run
    UV.gc
    true
  end
end

assert_uv 'UV::FS.access' do
  remove_uv_test_tmpfile

  UV::FS.mkdir 'foo-bar'
  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write 'helloworld'
  f.close

  assert_nil UV::FS.access 'foo-bar/foo.txt', UV::FS::F_OK
  assert_kind_of UVError, UV::FS.access('foo-bar/f.txt', UV::FS::F_OK)
  UV::FS.access 'foo-bar/foo.txt', UV::FS::F_OK do |res, err|
    assert_nil res
    assert_nil err
    remove_uv_test_tmpfile
  end
  UV::FS.access 'foo-bar/f.txt', UV::FS::F_OK do |res|
    assert_kind_of UVError, res
    assert_equal :ENOENT, res.name
    remove_uv_test_tmpfile
  end
end

assert_uv 'UV::FS' do
  remove_uv_test_tmpfile

  test_str = 'helloworld'
  UV::FS.mkdir 'foo-bar'
  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write test_str
  f.close

  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_RDONLY, UV::FS::S_IREAD
  assert_equal 'hello', f.read(5)
  assert_equal test_str, f.read
  f.close

  remove_uv_test_tmpfile
end

assert_uv 'UV::FS.scandir' do
  remove_uv_test_tmpfile

  test_str = 'helloworld'
  UV::FS.mkdir 'foo-bar'

  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write(test_str)
  f.close

  f = UV::FS.open 'foo-bar/bar.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write(test_str)
  f.close

  UV::FS.mkdir 'foo-bar/dir'

  res = [['bar.txt', :file], ['dir', :dir], ['foo.txt', :file]]

  # sync version
  a = UV::FS.scandir 'foo-bar', 0
  if a[0][1] == :unknown
    remove_uv_test_tmpfile
    skip
  end
  assert_equal res, a.sort

  # async version
  UV::FS.scandir 'foo-bar', 0 do |d|
    assert_equal res, d.sort

    remove_uv_test_tmpfile
  end
end

assert_uv 'UV::FS.symlink' do
  assert_true UV::FS::SYMLINK_DIR.kind_of? Numeric
  assert_true UV::FS::SYMLINK_JUNCTION.kind_of? Numeric
end

assert_uv 'UV::FS.readlink' do
  remove_uv_test_tmpfile
  UV::FS.mkdir 'foo-bar'

  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  UV::FS.symlink 'foo-bar/foo.txt', 'foo-bar/bar.txt'

  # async version
  UV::FS.readlink 'foo-bar/bar.txt' do |v|
    assert_equal 'foo-bar/foo.txt', v
    remove_uv_test_tmpfile
  end

  # sync version
  assert_equal 'foo-bar/foo.txt', UV::FS.readlink('foo-bar/bar.txt')
end

assert_uv 'UV::FS.realpath' do
  skip unless UV::FS.respond_to? :realpath

  # async version
  UV::FS.realpath '.' do |v|
    assert_kind_of String, v
  end

  # sync version
  assert_kind_of String, UV::FS.realpath('..')
end

assert_uv 'UV::FS.copyfile' do
  skip unless UV::FS.respond_to? :realpath

  remove_uv_test_tmpfile
  UV::FS.mkdir 'foo-bar'

  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  # async version
  UV::FS.copyfile 'foo-bar/foo.txt', 'foo-bar/bar.txt' do |v|
    assert_equal "test\n", UV::FS.open('foo-bar/bar.txt', UV::FS::O_RDONLY, UV::FS::S_IREAD).read(5)
    remove_uv_test_tmpfile
  end
end

assert_uv 'UV::FS.mkdtemp' do
  tmp = UV::FS.mkdtemp('temp_XXXXXX')
  assert_equal 'temp_', tmp[0, 5]
  UV::FS.rmdir tmp

  UV::FS.mkdtemp 'temp_XXXXXX' do |v|
    assert_equal 'temp_', v[0, 5]
    assert_equal 11, v.length
    UV::FS.rmdir v
  end
end

assert_uv 'UV::Stat' do
  remove_uv_test_tmpfile
  UV::FS.mkdir 'foo-bar'

  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  assert_raise(NoMethodError) { UV::Stat.new }

  s = UV::FS.stat 'foo-bar/foo.txt'
  assert_true s.kind_of? UV::Stat
  assert_true s.atim.kind_of? Time

  remove_uv_test_tmpfile
end

assert_uv 'UV.getaddrinfo' do
  req = UV.getaddrinfo('localhost', 'http') { |x, a|
    next unless a

    assert_equal 80, a.addr.sin_port
  }
  assert_kind_of UV::Req, req
  assert_equal :getaddrinfo, req.type_name

  # getaddrinfo without callback
  assert_raise(ArgumentError) { UV.getaddrinfo 'example.com', 'http' }
end

assert_uv 'UV.getnameinfo' do
  req = UV.getnameinfo(UV::Ip4Addr.new('127.0.0.1', 80)) { |host, service|
    assert_kind_of String, host
    assert_kind_of String, service
  }
  assert_kind_of UV::Req, req
  assert_equal :getnameinfo, req.type_name

  assert_raise(ArgumentError) { UV.getnameinfo UV::Ip4Addr.new('127.0.0.1', 80) }
end

assert_uv 'UV::Async' do
  async_called = false
  a = UV::Async.new do |async_state|
    async_called = true
  end

  t = UV::Timer.new
  p = UV::Prepare.new
  repeat_count = 0
  p.start do
    t.start UV_INTERVAL, UV_INTERVAL do
      a.send
      repeat_count += 1
      if repeat_count >= 3
        t.close
        a.close
        p.close
        assert_true async_called
      end
    end
  end
end

assert_uv 'UV::Timer' do
  t = UV::Timer.new
  c = 3
  t.start UV_INTERVAL, UV_INTERVAL do
    c -= 1
    t.close if c < 0
  end
end

assert 'UV::Loop' do
  l = UV::Loop.new
  t = UV::Timer.new l
  i = 3
  t.start UV_INTERVAL, UV_INTERVAL do
    i -= 1
    t.close if i < 0
  end
  l.run
  l.close
  assert_equal(-1, i)
end

assert_uv 'UV::Signal' do
  skip if UV::IS_WINDOWS || !UV::Signal.const_defined?(:SIGUSR1)

  s = UV::Signal.new
  s.start UV::Signal::SIGUSR1 do |x|
    assert_equal UV::Signal::SIGUSR1, x
    s.close
  end

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    raise_signal UV::Signal::SIGUSR1
    t.close
  end
end

assert_uv 'UV::Pipe' do
  path = UV::IS_WINDOWS ? '\\\\.\\pipe\\mruby-uv' : '/tmp/mruby-uv'
  s = UV::Pipe.new true
  s.bind path
  s.listen 5 do |x|
    return unless x.nil?
    c = s.accept
    c.write "helloworld\r\n"
    c.close
    s.close
  end

  assert_kind_of Fixnum, s.recv_buffer_size
  s.recv_buffer_size = 0x10000
  assert_true s.recv_buffer_size >= 0x10000

  assert_kind_of Fixnum, s.send_buffer_size
  s.send_buffer_size = 0x10000
  assert_true s.send_buffer_size >= 0x10000

  assert_kind_of Fixnum, s.fileno

  client = UV::Pipe.new true
  client.connect path do |x|
    if x.nil?
      assert_kind_of String, client.peername if client.respond_to? :peername
      assert_kind_of String, client.sockname

      client.read_start do |b|
        assert_equal "helloworld\r\n", b.to_s
        client.close
      end
    else
      client.close
    end
  end
end

assert_uv 'UV::UDP server/client' do
  test_str = 'helloworld'

  r6 = UV::UDP.new
  assert_kind_of Integer, r6.send_queue_count
  assert_kind_of Integer, r6.send_queue_size
  r6.bind6 UV.ip6_addr('::1', 8888)
  assert_equal '::1:8888', r6.getsockname.to_s
  r6.recv_start do |data, addr, flags|
    assert_equal test_str, data
    r6.close
  end

  r = UV::UDP.new
  r.bind UV.ip4_addr('127.0.0.1', 8888)
  assert_equal '127.0.0.1:8888', r.getsockname.to_s
  r.recv_start do |data, addr, flags|
    assert_equal test_str, data
    r.close
  end

  c6 = UV::UDP.new
  c6.send6 test_str, UV::ip6_addr('::1', 8888) do |x|
    c6.close
  end

  c = UV::UDP.new
  c.send test_str, UV::ip4_addr('127.0.0.1', 8888) do |x|
    c.close
  end
end

assert_uv 'UV::Prepare, UV::Check' do
  prep_called = false
  count = 0
  prep = UV::Prepare.new
  check = UV::Check.new
  timer = UV::Timer.new

  timer.start UV_INTERVAL, UV_INTERVAL do
    timer.close if count >= 3
  end

  prep.start do
    prep.close if count >= 3
    assert_false prep_called
    prep_called = true
  end

  check.start do
    check.close if count >= 3
    assert_true prep_called
    prep_called = false
    count += 1
  end
end

assert_uv 'UV::Idle' do
  i = UV::Idle.new
  idle_count = 0
  i.start do
    idle_count += 1
    i.close { assert_equal 3, idle_count } if idle_count >= 3
  end
end

assert_uv 'UV::TCP IPv6 server/client' do
  test_str = "helloworl\r\n"

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    c = UV::TCP.new
    assert_kind_of Integer, c.write_queue_size
    c.connect6 UV.ip6_addr('::1', 8888) do |connect_status|
      assert_nil connect_status
      c.read_start do |b|
        assert_equal test_str, b.to_s
        c.close
      end
    end

    t.close
  end

  s = UV::TCP.new
  s.bind6 UV.ip6_addr '::1', 8888
  assert_equal '::1:8888', s.getsockname.to_s
  s.listen 5 do |x|
    return unless x.nil?
    c = s.accept
    c.write test_str
    c.close
    s.close
  end
end

assert_uv 'UV::TCP IPv4 server/client' do
  test_str = "helloworld\r\n"

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    c = UV::TCP.new
    c.connect UV.ip4_addr('127.0.0.1', 8888) do |connect_status|
      assert_nil connect_status
      c.read_start do |b|
        assert_equal test_str, b
        c.close
      end
    end
    t.close
  end

  s = UV::TCP.new
  s.bind UV.ip4_addr '127.0.0.1', 8888
  assert_equal '127.0.0.1:8888', s.getsockname.to_s
  s.listen 5 do |x|
    return unless x.nil?
    c = s.accept
    assert_equal '127.0.0.1', c.getpeername.to_s[0, 9]
    c.write test_str
    s.close
  end
end

assert_uv 'UV::FS::Event rename' do
  remove_uv_test_tmpfile

  UV::FS::mkdir 'foo-bar'
  f = UV::FS::open "foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  ev = UV::FS::Event.new
  ev.start 'foo-bar', 0 do |rename_path, rename_ev|
    assert_equal 'foo.txt', rename_path
    assert_equal :rename, rename_ev
    assert_equal UV::FS::Event::RENAME, rename_ev
    ev.close
    remove_uv_test_tmpfile
  end
  assert_equal 'foo-bar', ev.path

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    UV::FS.rename 'foo-bar/foo.txt', 'foo-bar/bar.txt'
  end
end

assert_uv 'UV::FS::Event change' do
  remove_uv_test_tmpfile

  UV::FS.mkdir 'foo-bar'
  f = UV::FS.open "foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  ev = UV::FS::Event.new
  ev.start 'foo-bar/foo.txt', 0 do |change_path, change_ev|
    assert_equal 'foo.txt', change_path
    assert_equal :change, change_ev
    assert_equal UV::FS::Event::CHANGE, change_ev
    ev.close
    remove_uv_test_tmpfile
  end
  assert_equal 'foo-bar/foo.txt', ev.path

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    f = UV::FS.open "foo-bar/foo.txt", UV::FS::O_TRUNC|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
    f.write "test change\n"
    f.close
  end
end

assert_uv 'Process' do
  remove_uv_test_tmpfile
  UV::FS.mkdir 'foo-bar'
  f = UV::FS.open "foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write "test\n"
  f.close

  out = UV::Pipe.new(false)
  ps = UV::Process.new file: :grep, args: %w[-r test foo-bar], stdio: [nil, out, nil]

  ps.spawn do |x, sig|
    assert_equal 0, x # exit should be success
    assert_equal 0, sig # exit should be success

    assert_equal UV.default_loop, ps.loop
    assert_equal :process, ps.type_name
    assert_kind_of Integer, ps.pid

    ps.close
    remove_uv_test_tmpfile
  end

  str = ''
  out.read_start do |b|
    if b.kind_of? String
      str << b
      next
    end
    assert_equal "foo-bar/foo.txt:test\n", str
    out.close
  end

  env_out = UV::Pipe.new(false)
  UV::Process.new(file: :sh, args: ['-c', 'echo $a'], 'env' => { a: :test }, stdio: [nil, env_out, nil]).spawn do |x, sig|
    assert_equal 0, x
    assert_equal 0, sig
  end

  env_str = ''
  env_out.read_start do |b|
    if b.kind_of? String
      env_str << b
      next
    end
    assert_equal "test\n", env_str
    env_out.close
  end
end
