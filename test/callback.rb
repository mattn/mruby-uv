UV_INTERVAL = 2

def remove_uv_test_tmpfile
  UV::FS.unlink(UV::IS_WINDOWS ? '\\\\.\\pipe\\mruby-uv' : '/tmp/mruby-uv') rescue nil
  UV::FS.unlink 'foo-bar/bar.txt' rescue nil
  UV::FS.unlink 'foo-bar/foo.txt' rescue nil
  UV::FS.rmdir 'foo-bar' rescue nil
end

def assert_uv(name, &block)
  assert name do
    block.call
    UV.run
    true
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
  assert_equal test_str, f.read()
  f.close

  remove_uv_test_tmpfile
end

assert_uv 'UV::FS::readdir' do
  remove_uv_test_tmpfile

  test_str = 'helloworld'
  UV::FS.mkdir 'foo-bar'
  f = UV::FS.open 'foo-bar/foo.txt', UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write(test_str)
  UV::FS.readdir 'foo-bar', 0 do |x, a|
    assert_equal ['foo.txt'], a
  end

  remove_uv_test_tmpfile
end

assert_uv 'UV.getaddrinfo' do
  UV.getaddrinfo 'www.google.com', 'http' do |x, a|
    next unless a

    assert_equal 80, a.addr.sin_port
  end
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
  assert_equal(-1, i)
end

assert_uv 'UV::Signal' do
  skip if UV::IS_WINDOWS

  s = UV::Signal.new
  s.start UV::Signal::SIGWINCH do |x|
    assert_equal UV::Signal::SIGWINCH, x
    s.close
  end

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    raise_signal UV::Signal::SIGWINCH
    t.close
  end
end

assert_uv 'UV::Pipe' do
  path = UV::IS_WINDOWS ? '\\\\.\\pipe\\mruby-uv' : '/tmp/mruby-uv'
  s = UV::Pipe.new 1
  s.bind path
  s.listen 5 do |x|
    return if x != 0
    c = s.accept
    c.write "helloworld\r\n"
    c.close
    s.close
  end

  client = UV::Pipe.new(1)
  client.connect path do |x|
    if x == 0
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

assert_uv 'UV::TCP IPv4 server/client' do
  test_str = "helloworld\r\n"

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    c = UV::TCP.new
    c.connect UV.ip4_addr('127.0.0.1', 8888) do |connect_status|
      assert_equal 0, connect_status
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
    return if x != 0
    c = s.accept
    assert_equal '127.0.0.1', c.getpeername.to_s[0, 9]
    c.write test_str
    s.close
  end
end

assert_uv 'UV::TCP IPv6 server/client' do
  test_str = "helloworl\r\n"

  t = UV::Timer.new
  t.start UV_INTERVAL, 0 do
    c = UV::TCP.new
    c.connect6 UV.ip6_addr('::1', 8888) do |connect_status|
      assert_equal 0, connect_status
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
    return if x != 0
    c = s.accept
    c.write test_str
    c.close
    s.close
  end
end

assert_uv 'UV::FS::Event rename' do
  remove_uv_test_tmpfile

  UV::FS::mkdir 'foo-bar'
  f = UV::FS::open "foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD
  f.write 'test\n'
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
  t.start 10, 0 do
    f.write "test\n"
    UV::FS.fsync f.fd
    f.close
  end
end

assert_uv 'Process' do
  remove_uv_test_tmpfile
  UV::FS.mkdir 'foo-bar'

  ps = UV::Process.new 'file' => 'grep', 'args' => []
  ps.stdout_pipe = UV::Pipe.new 0

  ps.spawn do |sig|
    assert_equal 2, sig
    remove_uv_test_tmpfile
  end
  ps.stdout_pipe.read_start do |b|
    assert_nil b
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
