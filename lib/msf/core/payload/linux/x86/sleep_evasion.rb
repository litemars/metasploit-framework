module Msf::Payload::Linux::X86::SleepEvasion

    STUB_SLEEP_SECONDS_OFFSET = 0x02

    def sleep_stub
      stub = ""

      # 0x00: jmp 0x12                   ; jump forward to code (skip data section)
      stub << [0xeb, 0x10].pack('C*')
      # 0x02: timespec.tv_sec (4 bytes)  ; sleep duration in seconds (patched later)
      stub << "\x00\x00\x00\x00"
      # 0x06: timespec.tv_nsec (4 bytes) ; nanoseconds component (always 0)
      stub << "\x00\x00\x00\x00"
      # 0x0a: reserved (8 bytes)         ; alignment padding
      stub << "\x00\x00\x00\x00\x00\x00\x00\x00"
      # 0x12: call 0x17                  ; push next instruction address to stack
      stub << [0xe8, 0x00, 0x00, 0x00, 0x00].pack('C*')
      # 0x17: pop ebx                    ; ebx = current EIP
      stub << [0x5b].pack('C*')
      # 0x18: sub ebx, 0x15              ; ebx -> timespec structure (ebx - 21 bytes)
      stub << [0x83, 0xeb, 0x15].pack('C*')
      # 0x1b: xor ecx, ecx               ; ecx = NULL (remaining time pointer)
      stub << [0x31, 0xc9].pack('C*')
      # 0x1d: mov eax, 162               ; syscall number for nanosleep (0xa2)
      stub << [0xb8, 0xa2, 0x00, 0x00, 0x00].pack('C*')
      # 0x22: int 0x80                   ; invoke syscall
      stub << [0xcd, 0x80].pack('C*')
      # 0x24: execution continues to appended payload

      stub
    end

    def sleep_evasion(opts = {})
      seconds = opts[:seconds] || 0
      return "" if seconds == 0

      stub = sleep_stub.dup
      stub[STUB_SLEEP_SECONDS_OFFSET, 4] = [seconds].pack('V')
      stub
    end

    def sleep_stub_size
      36
    end

end
