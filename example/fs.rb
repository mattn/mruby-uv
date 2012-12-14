#!mruby
#f = UV::FS::open("foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE)
#f.write("fooo")
#f.close()

f = UV::FS::open("foo.txt", UV::FS::O_RDONLY) {
  puts f.read(3)
  puts f.read()
  f.close()
}

#UV::FS::unlink("foo.txt")
#UV::FS::mkdir("foo-bar")
#UV::FS::rmdir("foo-bar")

UV::run()
