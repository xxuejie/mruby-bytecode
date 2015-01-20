module Bytecode
  class Bytecode
    attr_accessor :header
    attr_accessor :sections
  end

  class BinaryHeader
    attr_accessor :binary_identify, :binary_version
    attr_accessor :binary_crc, :binary_size
    attr_accessor :compiler_name, :compiler_version
  end

  class SectionIrep
    IDENTIFIER = "IREP"

    attr_accessor :rite_version
    attr_accessor :record

    attr_accessor :debug_section
  end

  class IrepRecord
    attr_accessor :num_local, :num_register

    attr_accessor :opcodes
    attr_accessor :pools
    attr_accessor :symbols
    attr_accessor :child_ireps

    attr_accessor :debug_record
  end

  class SectionDebug
    IDENTIFIER = "DBG\0"

    attr_accessor :record
  end

  class DebugFileRecord
    attr_accessor :position
    attr_accessor :filename
    attr_accessor :entries
  end

  class DebugIrepRecord
    attr_accessor :file_records
    attr_accessor :child_records
  end

  class SectionLineno
    IDENTIFIER = "LINE"
  end

  class SectionLv
    IDENTIFIER = "LVAR"
  end

  EOF_IDENTIFIER = "END\0"

  module Parser
    class Error < StandardError; end
    class InvalidBytecodeVersion < Error; end
    class InvalidCrc < Error; end
    class InvalidFormat < Error; end

    CURRENT_BYTECODE_VERSION = "0003"

    CRC_16_CCITT = 0x11021
    CRC_XOR_PATTERN = (CRC_16_CCITT << 8)
    CRC_CARRY_BIT = 0x01000000
    CHAR_BIT = 8

    DUMP_NULL_SYM_LEN = 0xFFFF

    POOL_TYPE_STRING = 0x0
    POOL_TYPE_FIXNUM = 0x1
    POOL_TYPE_FLOAT = 0x2

    DEBUG_LINE_ARRAY = 0x0
    DEBUG_LINE_FLAT_MAP = 0x1

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
        t = bytes.getbyte(cur)
        cur += 1
        len = bytes[cur, 2].unpack("n")[0]
        cur += 2
        val = bytes[cur, len]
        cur += len
        record.pools <<
          case t
          when POOL_TYPE_FLOAT
            val.to_f
          when POOL_TYPE_FIXNUM
            val.to_i
          when POOL_TYPE_STRING
            val
          else
            val
          end
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

    def self.parse_debug_record(bytes, cur, irep, filenames)
      record = DebugIrepRecord.new
      # Skip record size
      cur += 4
      file_count = bytes[cur, 2].unpack("n")[0]
      cur += 2
      record.file_records = []
      file_count.times do
        file_record = DebugFileRecord.new
        position = bytes[cur, 4].unpack("N")[0]
        cur += 4
        file_record.position = position
        filename_index = bytes[cur, 2].unpack("n")[0]
        cur += 2
        filename = filenames[filename_index]
        file_record.filename = filename
        line_entry_count = bytes[cur, 4].unpack("N")[0]
        cur += 4
        line_type = bytes.getbyte(cur)
        cur += 1
        file_record.entries = []
        if line_type == DEBUG_LINE_ARRAY
          line_entry_count.times do
            file_record.entries << bytes[cur, 2].unpack("n")[0]
            cur += 2
          end
        elsif line_type == DEBUG_LINE_FLAT_MAP
          entries = {}
          line_entry_count.times do
            file_record.entries << bytes[cur, 6].unpack("Nn")
            cur += 6
          end
        else
          raise InvalidFormat
        end
        record.file_records << file_record
      end
      record.child_records = []
      irep.child_ireps.each do |child_irep|
        child_debug_record, cur = parse_debug_record(bytes, cur, child_irep, filenames)
        record.child_records << child_debug_record
      end
      irep.debug_record = record
      [record, cur]
    end

    def self.parse_debug_section(bytes, cur, irep_section)
      section = SectionDebug.new
      cur += 4
      size = bytes[cur, 4].unpack('N')[0]
      cur += 4
      filename_len = bytes[cur, 2].unpack("n")[0]
      cur += 2
      filenames = []
      filename_len.times do
        sym_len = bytes[cur, 2].unpack("n")[0]
        cur += 2
        filenames << bytes[cur, sym_len]
        cur += sym_len
      end
      section.record, cur = parse_debug_record(bytes, cur, irep_section.record, filenames)
      irep_section.debug_section = section
      [section, cur]
    end

    def self.parse_section(bytes, cur, irep_section)
      id = bytes[cur, 4]
      if id == "END\0"
        [nil, 8]
      else
        case id
        when SectionIrep::IDENTIFIER
          parse_irep_section(bytes, cur)
        when SectionDebug::IDENTIFIER
          parse_debug_section(bytes, cur, irep_section)
        else
          [id, bytes[cur + 4, 4].unpack("N")[0] + cur]
        end
      end
    end

    def self.parse(bytes)
      bytecode = Bytecode.new
      bytecode.header, cur = parse_binary_header(bytes, 0)
      bytecode.sections = []
      irep_section = nil
      section, cur = parse_section(bytes, cur, irep_section)
      while section
        irep_section = section if section.is_a? SectionIrep
        bytecode.sections <<= section
        section, cur = parse_section(bytes, cur, irep_section)
      end
      bytecode
    end

    def self.parse_file(filename)
      parse(File.read(filename))
    end
  end
end
