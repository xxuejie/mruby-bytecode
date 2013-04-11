module Bytecode
  class RiteBinaryHeader
    attr_accessor :binary_identify, :binary_version
    attr_accessor :binary_crc, :binary_size
    attr_accessor :compiler_name, :compiler_version
  end

  class RiteSectionHeader
    attr_accessor :section_identify, :section_size
  end

  class RiteSectionIrepHeader
    attr_accessor :section_header
    attr_accessor :rite_version, :nirep, :sirep
  end

  class RiteSectionLinenoHeader
    attr_accessor :section_header
    attr_accessor :nirep, :sirep
  end

  class RiteBinaryFooter
    attr_accessor :section_header
  end
end
