#!mruby

c = UV::UDP.new()
c.send6("helloworld", UV::ip6_addr('::1', 8888)) {|x|
  c.close()
}
UV::run()
