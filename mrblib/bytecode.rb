module Bytecode
  class BinaryHeader
    attr_accessor :binary_identify, :binary_version
    attr_accessor :binary_crc, :binary_size
    attr_accessor :compiler_name, :compiler_version
  end

  class SectionHeader
    attr_accessor :section_identify, :section_size
  end

  class SectionIrepHeader
    attr_accessor :section_header
    attr_accessor :rite_version
  end

  class SectionLinenoHeader
    attr_accessor :section_header
  end

  class SectionDebugHeader
    attr_accessor :section_header
  end

  class SectionLvHeader
    attr_accessor :section_header
  end

  class BinaryFooter
    attr_accessor :section_header
  end

  module Parser
    class Error < StandardError; end
    class InvalidBytecodeVersion < Error; end
    class InvalidCrc < Error; end

    CURRENT_BYTECODE_VERSION = "0003"

    CRC_16_CCITT = 0x11021
    CRC_XOR_PATTERN = (CRC_16_CCITT << 8)
    CRC_CARRY_BIT = 0x01000000
    CHAR_BIT = 8

    def self.crc(bytes, crc = 0)
      crcwk = crc << 8;
      bytes.each_byte do |c|
        crcwk |= c
        CHAR_BIT.times do
          # 32-bit
          crcwk = (crcwk << 1) & 0xFFFFFFFF
          if crcwk & CRC_CARRY_BIT != 0
            crcwk ^= CRC_XOR_PATTERN
          end
        end
      end
      # 16-bit
      (crcwk >> 8) & 0xFFFF
    end

    def self.parse_binary_header(bytes)
      header = BinaryHeader.new
      cur = 0
      header.binary_identify = bytes[cur, 4]
      cur += 4
      header.binary_version = bytes[cur, 4]
      cur += 4
      raise InvalidBytecodeVersion unless header.binary_version == CURRENT_BYTECODE_VERSION
      header.binary_crc, header.binary_size = bytes[cur, 6].unpack("nN")
      cur += 6
      crc_content = bytes[10, header.binary_size]
      raise InvalidCrc unless header.binary_crc == crc(crc_content)
      header.compiler_name = bytes[cur, 4]
      cur += 4
      header.compiler_version = bytes[cur, 4]
      cur += 4
      [header, cur]
    end
  end
end
