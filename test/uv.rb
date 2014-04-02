def assert_uv(name, &block)
  assert(name) do
    block.call
    UV::run
    true
  end
end

def remove_uv_test_tmpfile
  UV::FS::unlink 'foo-bar/foo.txt' rescue nil
  UV::FS::rmdir 'foo-bar' rescue nil
end

assert('UV.guess_handle') do
  assert_equal :tty, UV.guess_handle(0)
  assert_equal :tty, UV.guess_handle(1)
  assert_equal :tty, UV.guess_handle(2)
end

assert_uv('UV::getaddrinfo') do
  UV::getaddrinfo("www.google.com", "http") do |x, a|
    next unless a

    assert_equal 80, a.addr.sin_port
  end
end

assert_uv('UV::Async') do
  async_called = false
  a = UV::Async.new do |async_state|
    async_called = true
  end

  t = UV::Timer.new
  p = UV::Prepare.new
  repeat_count = 0
  p.start do
    t.start(10, 10) do
      a.send
      repeat_count += 1
      if repeat_count >= 3
        t.stop
        t.close
        a.close
        p.close
        assert_true async_called
      end
    end
  end
end

assert_uv('UV::FS') do
  test_str = 'helloworld'
  remove_uv_test_tmpfile
  UV::FS::mkdir("foo-bar") do
    f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD)
    f.write(test_str) do
      f.close do
        f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_RDONLY, UV::FS::S_IREAD) do
          assert_equal 'hello', f.read(5)
          assert_equal test_str, f.read()
          f.close { remove_uv_test_tmpfile }
        end
      end
    end
  end
end

assert_uv('UV::Idle') do
  i = UV::Idle.new
  idle_count = 0
  i.start do
    idle_count += 1
    if idle_count >= 3
      i.close
    end
  end
end

assert('UV::Loop') do
  l = UV::Loop.new
  t = UV::Timer.new l
  i = 3
  t.start(10, 10) do
    i -= 1
    if i < 0
      t.stop
      t.close
    end
  end
  l.run
  true
end

assert_uv('UV::Pipe') do
  if UV::IS_WINDOWS
    s = UV::Pipe.new(0)
    s.bind('\\\\.\\pipe\\mruby-uv')
    s.listen(5) do |x|
      return if x != 0
      c = s.accept()
      c.write "helloworld\r\n"
      c.close()
      s.close
    end

    client = UV::Pipe.new(0)
    client.connect('\\\\.\\pipe\\mruby-uv') do |x|
      if x == 0
        client.read_start do |b|
          assert_equal "helloworld\r\n", b.to_s
          client.close
        end
      else
        client.close
      end
    end
  else
    s = UV::Pipe.new 1
    s.bind '/tmp/mruby-uv'
    s.listen(5) do |x|
      return if x != 0
      c = s.accept
      c.write "helloworld\r\n"
      c.close
      s.close
    end

    client = UV::Pipe.new(1)
    client.connect('/tmp/mruby-uv') do |x|
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
end

assert_uv('Process') do
  remove_uv_test_tmpfile
  UV::FS::mkdir 'foo-bar'

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

assert_uv('UV::FS::readdir') do
  test_str = 'helloworld'
  remove_uv_test_tmpfile
  UV::FS::mkdir("foo-bar") do
    f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD)
    f.write(test_str) do
      UV::FS::readdir("foo-bar", 0) do |x,a|
        assert_equal ['foo.txt'], a
        remove_uv_test_tmpfile
      end
    end
  end
end

assert_uv('UV::Signal') do
  skip if UV::IS_WINDOWS
  s = UV::Signal.new
  s.start(UV::Signal::SIGINT) do |x|
    assert_equal UV::Signal::SIGINT, x
    s.close
  end

  t = UV::Timer.new
  t.start(10, 0) do
    raise_signal UV::Signal::SIGINT
    t.close
  end
end

assert_uv('UV::TCP IPv4 server/client') do
  test_str = "helloworld\r\n"

  t = UV::Timer.new
  t.start(10, 0) do
    c = UV::TCP.new
    c.connect(UV.ip4_addr('127.0.0.1', 8888)) do |connect_status|
      assert_equal 0, connect_status
      c.read_start do |b|
        assert_equal test_str, b
        c.close
      end
    end
    t.close
  end

  s = UV::TCP.new
  s.bind UV::ip4_addr '127.0.0.1', 8888
  assert_equal '127.0.0.1:8888', s.getsockname.to_s
  s.listen(5) do |x|
    return if x != 0
    c = s.accept
    assert_equal '127.0.0.1', c.getpeername.to_s[0, 9]
    c.write test_str
    s.close
  end
end

assert_uv('UV::TCP IPv6 server/client') do
  test_str = "helloworl\r\n"

  t = UV::Timer.new
  t.start(10, 0) do
    c = UV::TCP.new
    c.connect6(UV.ip6_addr('::1', 8888)) do |connect_status|
      assert_equal 0, connect_status
      c.read_start do |b|
        assert_equal test_str, b.to_s
        c.close
      end
    end

    t.close
  end

  s = UV::TCP.new
  s.bind6 UV::ip6_addr '::1', 8888
  assert_equal '::1:8888', s.getsockname.to_s
  s.listen(5) do |x|
    return if x != 0
    c = s.accept
    c.write test_str
    c.close
    s.close
  end
end

assert_uv('UV::Timer') do
  t = UV::Timer.new
  c = 3
  t.start(10, 10) do
    c -= 1
    if c < 0
      t.stop
      t.close
    end
  end
end

assert('UV::TTY') do
  tty = UV::TTY.new(1, 1)
  tty.set_mode(0)
  tty.reset_mode
  win = tty.get_winsize
  assert_true win[0].kind_of? Fixnum
  assert_true win[1].kind_of? Fixnum
  tty.close
  true
end

assert_uv('UV::UDP server/client') do
  test_str = 'helloworld'

  r6 = UV::UDP.new()
  r6.bind6(UV::ip6_addr('::1', 8888))
  assert_equal '::1:8888', r6.getsockname.to_s
  r6.recv_start do |data, addr, flags|
    assert_equal test_str, data
    r6.close
  end

  r = UV::UDP.new()
  r.bind(UV::ip4_addr('127.0.0.1', 8888))
  assert_equal '127.0.0.1:8888', r.getsockname.to_s
  r.recv_start do |data, addr, flags|
    assert_equal test_str, data
    r.close
  end

  c6 = UV::UDP.new()
  c6.send6(test_str, UV::ip6_addr('::1', 8888)) do |x|
    c6.close
  end

  c = UV::UDP.new()
  c.send(test_str, UV::ip4_addr('127.0.0.1', 8888)) do |x|
    c.close
  end
end

assert('UV::Semaphore') do
  sem = UV::Semaphore.new 3
  sem.wait
  sem.wait
  assert_true sem.try_wait
  assert_false sem.try_wait

  sem.post
  assert_true sem.try_wait
  assert_false sem.try_wait

  assert_false sem.destroyed?
  sem.destroy
  assert_true sem.destroyed?
end

assert('UV.loadavg') do
  avg = UV.loadavg
  assert_equal 3, avg.length
  assert_true avg[0] >= 0.0
  assert_true avg[1] >= 0.0
  assert_true avg[2] >= 0.0
end

assert('UV.version') do
  assert_true UV.version.kind_of? Fixnum
end

assert('UV.version_string') do
  assert_true UV.version_string.kind_of? String
end

assert('UV.exepath') do
  if UV::IS_WINDOWS
    assert_equal 'mrbtest.exe', UV.exepath[-11, 11]
  else
    assert_equal 'mrbtest', UV.exepath[-7, 7]
  end
end

assert('UV.cwd') do
  assert_true UV.cwd.kind_of? String
end

assert('UV.free_memory') do
  assert_true UV.free_memory.kind_of? Numeric
end

assert('UV.total_memory') do
  assert_true UV.total_memory.kind_of? Numeric
  assert_true UV.free_memory <= UV.total_memory
end

assert('UV.hrtime') do
  assert_true UV.hrtime.kind_of? Numeric
end

assert('UV.process_title') do
  assert_true UV.process_title.kind_of? String
end

assert('UV.process_title=') do
  assert_true (UV.process_title = 'test').kind_of? String
end
