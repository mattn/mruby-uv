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
    __t_printstr__ str
    assert_equal "test\n", str
  end
  y.start
  y.loop.run

  assert_nil y.error
end
