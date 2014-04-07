#!mruby
begin; require 'mruby-uv'; rescue Exception; end

UV::FS::mkdir("foo-bar") do
  f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_CREAT|UV::FS::O_WRONLY, UV::FS::S_IWRITE | UV::FS::S_IREAD)
  f.write("helloworld") do
    f.close() do
      f = UV::FS::open("foo-bar/foo.txt", UV::FS::O_RDONLY, UV::FS::S_IREAD) do
        puts f.read(5)
        puts f.read()
        f.close() do
          UV::FS::unlink("foo-bar/foo.txt") do
            UV::FS::rmdir("foo-bar")
          end
        end
      end
    end
  end
end
UV::run()
