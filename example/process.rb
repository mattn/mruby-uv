#!mruby

UV::spawn({
  'file' => 'c:\\windows\\system32\\notepad.exe',
  'args' => []
}) do
  puts "exit"
end
UV::run()
