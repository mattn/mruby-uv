def assert_uv(name, &block)
  assert(name) do
    block.call
    UV::run
    true
  end
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
    assert_equal 0, async_state
    async_called = true
  end

  t = UV::Timer.new
  p = UV::Prepare.new
  repeat_count = 0
  p.start do |x|
    t.start(10, 10) do |timer_status|
      assert_equal 0, timer_status
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
  UV::FS::mkdir("foo-bar") do
    f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD)
    f.write("helloworld") do
      f.close do
        f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_RDONLY, UV::FS::S_IREAD) do
          assert_equal 'hello', f.read(5)
          assert_equal 'helloworld', f.read()
          f.close() do
            UV::FS::unlink("foo-bar/foo.txt") do
              UV::FS::rmdir("foo-bar")
            end
          end
        end
      end
    end
  end
end

assert_uv('UV::Idle') do
  i = UV::Idle.new
  idle_count = 0
  i.start do |x|
    assert_equal 0, x
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
  t.start(10, 10) do |x|
    assert_equal 0, x
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
    s.listen(1) do |x|
      return if x != 0
      c = s.accept()
      puts "connected"
      t = UV::Timer.new()
      t.start(10, 10) do |timer_status|
        assert_equal 0, timer_status
        puts "helloworld\n"
        begin
          c.write "helloworld\r\n"
        rescue RuntimeError
          c.close()
          t.stop()
          t = nil
        end
      end
    end

    c = UV::Pipe.new(0)
    c.connect('\\\\.\\pipe\\mruby-uv') do |x|
      if x == 0
        c.read_start do |b|
          puts b.to_s
        end
      else
        c.close
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
      client.read_start do |b|
        assert_equal "helloworld\r\n", b.to_s
        client.close
      end
    end
  end
end

assert_uv('Process') do
  UV::FS::mkdir 'foo-bar'

  ps = UV::Process.new 'file' => 'grep', 'args' => []
  ps.stdout_pipe = UV::Pipe.new 0

  ps.spawn do |sig|
    assert_equal 2, sig
    UV::FS::rmdir 'foo-bar'
  end
  ps.stdout_pipe.read_start do |b|
    assert_nil b
  end
end

assert_uv('UV::FS::readdir') do
  UV::FS::mkdir("foo-bar") do
    f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD)
    f.write("helloworld") do
      UV::FS::readdir("foo-bar", 0) do |x,a|
        assert_equal ['foo.txt'], a
        UV::FS::unlink("foo-bar/foo.txt") do
          UV::FS::rmdir("foo-bar")
        end
      end
    end
  end
end

assert_uv('UV::Signal') do
  s = UV::Signal.new
  s.start(UV::Signal::SIGINT) do |x|
    assert_equal UV::Signal::SIGINT, x
    s.close
  end

  t = UV::Timer.new
  t.start(10, 0) do |x|
    assert_equal 0, x
    raise_signal UV::Signal::SIGINT
    t.close
  end
end

assert_uv('UV::TCP IPv4 server/client') do
  test_str = "helloworld\r\n"

  t = UV::Timer.new
  t.start(10, 0) do |x|
    assert_equal 0, x

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
  s.listen(5) do |x|
    return if x != 0
    c = s.accept
    c.write test_str
    s.close
  end
end

assert_uv('UV::TCP IPv6 server/client') do
  test_str = "helloworl\r\n"

  t = UV::Timer.new
  t.start(10, 0) do |x|
    assert_equal 0, x

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
  t.start(10, 10) do |x|
    assert_equal 0, x
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
  r6.recv_start do |data, addr, flags|
    assert_equal test_str, data
    r6.close
  end

  r = UV::UDP.new()
  r.bind(UV::ip4_addr('127.0.0.1', 8888))
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
