module UV
  def self.sleep sec
    current_yarn.sleep sec
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

    def clear_current_yarn
      @current_yarn = nil
    end
  end

  class Yarn
    def initialize(loop = UV.current_loop, &blk)
      @fiber = Fiber.new(&blk)
      @loop = loop
    end

    attr_reader :loop, :error

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
      timer.start(sec * 1000.0, 0) do
        self.resume
      end
      Fiber.yield(timer, self)
    end

    def resume(*args)
      raise "cannot resume unstarted yarn" unless @started
      raise "cannot run ended yarn" if ended?

      @loop.current_yarn = self

      prev_loop = UV.current_loop
      @loop.make_current

      *ret = @fiber.resume(*args)

      if @fiber.alive?
        raise "invalid yield" if !ret.first.kind_of?(UV::Req) && !ret.first.kind_of?(UV::Timer)
      else
        @fiber = nil
        @result = ret
      end

    rescue => e
      @error = e

    ensure
      @loop.clear_current_yarn
      prev_loop.make_current if prev_loop
    end
  end
end
