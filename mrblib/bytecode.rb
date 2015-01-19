module Bytecode
  class BinaryHeader
    attr_accessor :binary_identify, :binary_version
    attr_accessor :binary_crc, :binary_size
    attr_accessor :compiler_name, :compiler_version
  end

  class SectionIrep
    IDENTIFIER = "IREP"

    attr_accessor :rite_version
    attr_accessor :record
  end

  class IrepRecord
    attr_accessor :num_local, :num_register

    attr_accessor :opcodes
    attr_accessor :pools
    attr_accessor :symbols
    attr_accessor :child_ireps
  end

  class SectionLineno
    IDENTIFIER = "LINE"
  end

  class SectionDebug
    IDENTIFIER = "DBG\0"
  end

  class SectionLv
    IDENTIFIER = "LVAR"
  end

  EOF_IDENTIFIER = "END\0"

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

    def self.parse_binary_header(bytes, cur)
      header = BinaryHeader.new
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

    DUMP_NULL_SYM_LEN = 0xFFFF

    def self.padding(cur)
      cur + ((- cur) & (4 - 1))
    end

    def self.parse_irep_record(bytes, cur)
      record = IrepRecord.new
      record_size, record.num_local, record.num_register, num_child = bytes[cur, 10].unpack("Nnnn")
      cur += 10
      num_opcode = bytes[cur, 4].unpack("N")[0]
      cur += 4
      cur = padding(cur)
      record.opcodes = bytes[cur, 4 * num_opcode].unpack("N" * num_opcode)
      cur += 4 * num_opcode
      num_pool = bytes[cur, 4].unpack("N")[0]
      cur += 4
      record.pools = []
      num_pool.times do
        t = bytes[cur]
        cur += 1
        len = bytes[cur, 2].unpack("n")[0]
        cur += 2
        record.pools << [t, bytes[cur, len]]
        cur += len
      end
      num_symbol = bytes[cur, 4].unpack("N")[0]
      cur += 4
      record.symbols = []
      num_symbol.times do
        len = bytes[cur, 2].unpack("n")[0]
        cur += 2
        if len == DUMP_NULL_SYM_LEN
          record.symbols << ""
        else
          record.symbols << bytes[cur, len]
          # Symbols are NULL-terminated
          cur += len + 1
        end
      end
      record.child_ireps = []
      num_child.times do
        child, cur = parse_irep_record(bytes, cur)
        record.child_ireps << child
      end
      [record, cur]
    end

    def self.parse_irep_section(bytes, cur)
      # Skipping header
      cur += 4
      section = SectionIrep.new
      size = bytes[cur, 4].unpack('N')[0]
      cur += 4
      section.rite_version = bytes[cur, 4]
      cur += 4
      section.record, cur = parse_irep_record(bytes, cur)
      [section, cur]
    end

    def self.parse_section(bytes, cur)
      id = bytes[cur, 4]
      if id == "END\0"
        [nil, 8]
      else
        case id
        when SectionIrep::IDENTIFIER
          parse_irep_section(bytes, cur)
        else
          [id, bytes[cur + 4, 4].unpack("N")[0] + cur]
        end
      end
    end

    def self.parse(bytes)
      header, cur = parse_binary_header(bytes, 0)
      sections = []
      section, cur = parse_section(bytes, cur)
      while section
        sections <<= section
        section, cur = parse_section(bytes, cur)
      end
      [header, sections]
    end

    def self.parse_file(filename)
      parse(File.read(filename))
    end
  end
end
