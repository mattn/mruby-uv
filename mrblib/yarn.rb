module UV
  def self.sleep sec
    if UV.current_loop.current_yarn
      current_yarn.sleep sec
    else
      UV.sleep_milli sec * 1000
    end
  end

  def self.quote cmd
    current_yarn.quote(cmd)
  end

  def self.current_yarn
    ret = UV.current_loop.current_yarn
    raise "yarn not running" if ret.nil?
    ret
  end

  class Loop
    attr_reader :current_yarn

    def current_yarn=(y)
      raise "cannot double run yarn" if current_yarn
      raise "not yarn" unless y.kind_of? UV::Yarn

      @current_yarn = y
    end

    def clear_current_yarn(y)
      raise 'cannot clear yarn' if y != @current_yarn
      @current_yarn = nil
    end
  end

  class Yarn
    def initialize(loop = UV.current_loop, &blk)
      @fiber = Fiber.new(&blk)
      @loop = loop
    end

    attr_reader :loop, :error, :req

    def ended?; @fiber.nil? end
    def result
      raise "not ended" unless ended?
      @result
    end

    def check_error
      raise @error if @error
    end

    def timer
      @timer ||= UV::Timer.new
      # raise 'timer already used' if @timer.active?
      @timer
    end

    def to_proc
      @proc ||= Proc.new{|*args, &blk| self.resume(*args, &blk) }
    end

    def start(*args)
      raise "already started" if @started
      @started = true

      resume(*args)
    end

    def sleep sec
      timer.start(sec * 1000.0, 0, &self.to_proc)
      Fiber.yield(timer, self)
    end

    def quote cmd
      out = UV::Pipe.new false
      ps = Process.new file: :sh, args: ['-c', cmd], stdio: [nil, out, nil]
      y = self
      ps.spawn do |x, sig|
        str = ''
        out.read_start do |b|
          if b.kind_of? String
            str.concat b
            next
          end
          y.resume(str)
          out.close
        end
      end
      Fiber.yield ps, self
    end

    def resume(*args)
      raise "cannot resume unstarted yarn" unless @started
      raise "cannot run ended yarn" if ended?

      @loop.current_yarn = self

      prev_loop = UV.current_loop
      @loop.make_current

      *ret = @fiber.resume(*args)

      if @fiber.alive?
        raise "invalid yield #{ret.inspect}" unless ALIVE_CLASSES.any?{|v| ret.first.kind_of? v }
      else
        @fiber = nil
        @result = ret
      end

    rescue => e
      @error = e

    ensure
      @loop.clear_current_yarn self
      prev_loop.make_current if prev_loop
    end

    ALIVE_CLASSES = [UV::Req, UV::Timer, UV::Process]
  end
end
