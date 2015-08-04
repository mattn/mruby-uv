assert('UV.guess_handle') do
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
  assert_equal :work, req.type
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

assert 'UV::SOMAXCONN' do
  assert_kind_of Fixnum, UV::SOMAXCONN
end

assert 'UV.thread_self' do
  s = UV.thread_self
  assert_equal s, s
end

assert 'UV.getaddrinfo ipv4' do
  UV::getaddrinfo('google.com', 'http', {:ai_family => :ipv4}) do |x, info|
    assert_true(info.addr.is_a?(UV::Ip4Addr), "Expected UV::Ip4Addr but got #{info.addr.class}")
  end
  UV::run()
end

assert 'UV.getaddrinfo ipv6' do
  UV::getaddrinfo('google.com', 'http', {:ai_family => :ipv6}) do |x, info|
    assert_true(info.addr.is_a?(UV::Ip6Addr), "Expected UV::Ip4Addr but got #{info.addr.class}")
  end
  UV::run()
end

assert 'UV.getaddrinfo' do
  req = UV::getaddrinfo('google.com', 'http') {}
  UV::run()

  assert_true req.is_a?(UV::Req)
end
