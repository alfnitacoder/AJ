; AJOS syscall interface (int 0x80)
; Registers:
;  - eax = syscall number
;  - ebx/ecx/edx = args (as specified per syscall)
;  - eax = return value

%define SYSCALL_WRITE   1   ; ebx=ptr, ecx=len -> eax=written
%define SYSCALL_TICKS   2   ; -> eax=ticks
%define SYSCALL_SLEEP   3   ; ebx=ms -> eax=0
%define SYSCALL_GETKEY  4   ; -> eax=keycode (same as kernel KEY_* values)
%define SYSCALL_EXIT    5   ; ebx=exit code -> does not return
%define SYSCALL_GETPID  6   ; -> eax=pid
%define SYSCALL_GETPPID 7   ; -> eax=parent pid
%define SYSCALL_FORK    16  ; -> eax=child pid in parent, 0 in child (-1 fail)
%define SYSCALL_EXECVE  17  ; ebx=path, ecx=argv, edx=envp -> replaces image
%define SYSCALL_WAITPID 18  ; ebx=pid(0=any), ecx=&status -> eax=reaped pid

; Common key codes (must match kernel.c)
%define KEY_UP      0x100
%define KEY_DOWN    0x101
%define KEY_LEFT    0x102
%define KEY_RIGHT   0x103
%define KEY_DELETE  0x104
%define KEY_INSERT  0x105
%define KEY_HOME    0x106
%define KEY_END     0x107

