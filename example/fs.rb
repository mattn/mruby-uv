#!mruby
f = UV::FS::open("foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE)
f.write("fooo")
f.close()

f = UV::FS::open("foo.txt", UV::FS::O_RDONLY|UV::FS::O_TEXT, UV::FS::S_IREAD)
data = f.read()
puts data
f.close()
