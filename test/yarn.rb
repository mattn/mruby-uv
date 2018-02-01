assert "Yarn" do
  y = UV::Yarn.new do
    t = UV.current_loop.now
    UV.sleep 0.1
    assert_true (UV.current_loop.now - t) >= 100
    UV.sleep 0.1
    assert_true (UV.current_loop.now - t) >= 200
  end

  y.start
  y.loop.run
end
