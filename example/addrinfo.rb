#!mruby
begin; require 'mruby-uv'; rescue Exception; end

UV::getaddrinfo("www.google.com", "http") do |x, a|
  if a
    puts "flags: #{a.flags}"
    puts "family: #{a.family}"
    puts "socktype: #{a.socktype}"
    puts "protocol: #{a.protocol}"
    puts "addr: #{a.addr}"
    puts "  sin_addr: #{a.addr.sin_addr}"
    puts "  sin_port: #{a.addr.sin_port}"
    puts "canonname: #{a.canonname}"
    puts "next: #{a.next}"
  end
end

UV::run()
