assert "Yarn sleep" do
  y = UV::Yarn.new do
    t = y.loop.now
    UV.sleep 0.1
    assert_true (y.loop.now - t) >= 100
    UV.sleep 0.1
    assert_true (y.loop.now - t) >= 200
  end

  y.start
  y.loop.run

  assert_nil y.error
end

assert 'Yarn process' do
  y = UV::Yarn.new do
    str = UV.quote('echo test')
    assert_equal "test\n", str
    str = UV.quote('echo test1')
    assert_equal "test1\n", str
  end
  y.start
  y.loop.run

  assert_nil y.error
end

assert 'Yarn DNS' do
  y = UV::Yarn.new do
    host, service = UV.getnameinfo(UV::Ip4Addr.new('127.0.0.1', 80))
    assert_kind_of String, host
    assert_equal 'http', service

    err, a = UV.getaddrinfo 'localhost', 'http'
    assert_nil err
    assert_equal 80, a.addr.sin_port
  end
  y.start
  y.loop.run
  assert_nil y.error
end
