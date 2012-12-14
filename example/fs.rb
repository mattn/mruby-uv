#!mruby

UV::FS::mkdir("foo-bar") do
  f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE)
  f.write("fooo")
  f.close() do
    f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_RDONLY) do
      puts f.read(3)
      puts f.read()
      f.close() do
        UV::FS::unlink("foo-bar/foo.txt") do
          UV::FS::rmdir("foo-bar")
        end
      end
    end
  end
end
UV::run()
