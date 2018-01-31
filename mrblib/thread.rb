module UV
  class Thread
    def != other; !(self == other) end
  end

  class Loop
    def != other; !(self == other) end
  end
end
