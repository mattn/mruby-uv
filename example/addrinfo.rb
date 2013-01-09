#!mruby

UV::getaddrinfo("www.google.com", "http") do |x, a|
  if a
    puts "flags: #{a.flags}"
    puts "family: #{a.family}"
    puts "socktype: #{a.socktype}"
    puts "protocol: #{a.protocol}"
    puts "addr: #{a.addr}"
    puts "canonname: #{a.canonname}"
    puts "next: #{a.next}"
  end
end

UV::run()
