; syscall_stub.asm - x64 assembly stub for direct syscall invocation
; Assembles with MASM (ml64.exe) on Windows
;
; Calling convention: Windows x64 (rcx, rdx, r8, r9 for first 4 args)
; 
; uint64_t do_syscall(uint32_t syscall_number,  ; ecx
;                     uint64_t arg1,            ; rdx
;                     uint64_t arg2,            ; r8
;                     uint64_t arg3,            ; r9
;                     uint64_t arg4);           ; [rsp+28h]

.code

do_syscall PROC
    ; Save the syscall number
    mov r10, rcx            ; Windows syscall convention: r10 = first arg (normally rcx)
    mov eax, ecx            ; syscall number goes in eax
    
    ; Shift arguments: arg1->rcx, arg2->rdx, arg3->r8, arg4->r9
    mov rcx, rdx            ; arg1 -> rcx
    mov rdx, r8             ; arg2 -> rdx
    mov r8, r9              ; arg3 -> r8
    mov r9, [rsp+28h]       ; arg4 -> r9 (from stack, accounting for return address + shadow space)
    
    ; Execute syscall
    syscall
    
    ; Return value is already in rax
    ret
do_syscall ENDP

END
