assert('UV.guess_handle') do
  skip if UV.guess_handle(0) == :pipe
  assert_equal :tty, UV.guess_handle(0)
  assert_equal :tty, UV.guess_handle(1)
  assert_equal :tty, UV.guess_handle(2)
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

assert('UV.rusage') do
  assert_true UV.rusage.kind_of? Hash
end

assert('UV.cpu_info') do
  i = UV.cpu_info
  assert_true i.kind_of? Array
  assert_true i.length > 0
end

assert('UV.interface_addresses') do
  assert_true UV.interface_addresses.kind_of? Array
end

assert('UV.queue_work') do
  c = 0
  assert_raise(ArgumentError) { UV.queue_work(Proc.new {}) {} }
  assert_raise(ArgumentError) { UV.queue_work(WorkCFunc) }
  req = UV.queue_work(WorkCFunc) {
    assert_equal 4950, get_work_result
    c += 1
  }
  assert_kind_of UV::Req, req
  assert_equal :work, req.type_name
  UV.run
  assert_equal 1, c
end

assert('UV.resident_set_memory') do
  assert_true UV.resident_set_memory.kind_of? Numeric
end

assert('UV.uptime') do
  assert_true UV.uptime.kind_of? Numeric
end

assert('UV::Once') do
  assert_raise(ArgumentError) { UV::Once.new }

  c = 0
  o = UV::Once.new { c += 1 }
  o.run
  assert_equal 1, c
  o.run
  assert_equal 1, c
end

assert 'UV::Req' do
  assert_raise(NoMethodError) { UV::Req.new }
end

assert 'UV::Loop#now' do
  assert_kind_of Numeric, UV.default_loop.now
end

assert 'UV::Loop#configure' do
  skip unless UV::default_loop.respond_to? :configure
  skip unless UV::Signal.const_defined? :SIGPROF
  UV.default_loop.configure block_signal: UV::Signal::SIGPROF
end

assert 'UV::Loop#make_current' do
  assert_equal UV.default_loop, UV.current_loop

  l = UV::Loop.new
  l.make_current
  assert_equal l, UV.current_loop

  UV.default_loop.make_current
  assert_equal UV.default_loop, UV.current_loop
end

assert 'UV::SOMAXCONN' do
  assert_kind_of Fixnum, UV::SOMAXCONN
end

assert 'UV.thread_self' do
  s = UV.thread_self
  assert_equal s, s
end

assert 'UV.getaddrinfo ipv4' do
  UV::getaddrinfo('localhost', 'http', {:ai_family => :ipv4}) do |x, info|
    assert_kind_of UV::Ip4Addr, info.addr
  end
  UV::run()
end

assert 'UV.getaddrinfo ipv6' do
  UV::getaddrinfo('example.com', 'http', {:ai_family => :ipv6}) do |x, info|
    addr = info.addr
    assert_kind_of UV::Ip6Addr, addr
    assert_kind_of Integer, addr.scope_id
    if addr.scope_id != 0 && addr.respond_to?(:if_indextoname)
      assert_kind_of String, addr.if_indextoname
      assert_kind_of String, addr.if_indextoiid
    end
  end
  UV::run()
end

assert 'UV.getaddrinfo.next' do
  UV::getaddrinfo('localhost', 'http') do |x, info|
    while info
      assert_kind_of UV::Addrinfo, info
      info = info.next
    end

    assert_nil info
  end
  UV::run()
end

assert 'UV.get_error' do
  err = UV::get_error(-1)
  assert_true err.is_a?(UVError)
  assert_equal :EPERM, err.name
  assert_equal 'operation not permitted', err.message
end

assert 'UV::Addrinfo constants' do
  assert_true UV::Addrinfo.const_defined? :AF_INET
  assert_true UV::Addrinfo.const_defined? :SOCK_STREAM
  assert_true UV::Addrinfo.const_defined? :AI_PASSIVE
  assert_true UV::Addrinfo.const_defined? :IPPROTO_TCP
end

assert 'UV::OS' do
  assert_kind_of String, UV::OS.homedir if UV::OS.respond_to? :homedir
  assert_kind_of String, UV::OS.tmpdir if UV::OS.respond_to? :tmpdir

  if UV::OS.respond_to? :getenv
    assert_kind_of String, UV::OS.getenv('HOME')
    assert_nil UV::OS.getenv('__gdsgdsgjsngjddsg')

    UV::OS.setenv "aaaaaaa", "bbb"
    assert_equal "bbb", UV::OS.getenv("aaaaaaa")
    UV::OS.unsetenv "aaaaaaa"
    assert_nil UV::OS.getenv "aaaaaaa"

    assert_kind_of String, UV::OS.hostname
  end

  assert_kind_of Integer, UV::OS.getppid if UV::OS.respond_to? :getppid
  assert_kind_of Integer, UV::OS.getpid if UV::OS.respond_to? :getpid
end

assert 'UV::OS::Passwd' do
  skip unless UV::OS.const_defined? :Passwd

  p = UV::OS::Passwd.new
  assert_kind_of String, p.username
  p.shell
  assert_kind_of String, p.homedir
  assert_kind_of Fixnum, p.uid
  assert_kind_of Fixnum, p.gid
end
