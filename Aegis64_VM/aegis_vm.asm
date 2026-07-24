bits 64
default rel

; VM Entry
vm_entry:
    mov [rel bytecode_base], rsi

    lea rax, [rel vm_entry]
    and rax, 0xFFFFFFFFFFFF0000  

; Beating ASLR   
.scan_mz:
    cmp word [rax], 0x5A4D          
    je .found_mz
    sub rax, 0x10000                
    jmp .scan_mz

; Initializing VM
.found_mz:
    mov [rel current_image_base], rax 

    push rax        ; Slot 17 placeholder (RFLAGS)
    push rax        ; Slot 16 placeholder (VIP)
    push r15        ; Slot 15
    push r14        ; Slot 14
    push r13        ; Slot 13
    push r12        ; Slot 12
    push r11        ; Slot 11
    push r10        ; Slot 10
    push r9         ; Slot 9
    push r8         ; Slot 8
    push rdi        ; Slot 7
    push rsi        ; Slot 6
    push rbp        ; Slot 5
    push rsp        ; Slot 4 placeholder (RSP)
    push rbx        ; Slot 3
    push rdx        ; Slot 2
    push rcx        ; Slot 1
    push rax        ; Slot 0

    ; Save actual RFLAGS into Slot 17
    pushfq
    pop rax
    mov [rsp + 17*8], rax

    ; Save the correct caller stack pointer into Slot 4
    lea rax, [rsp + 18*8]
    mov [rsp + 4*8], rax

    mov rbp, rsp                


; CORE DISPATCH LOOP
vm_loop:
    movzx rax, byte [rsi]           
    inc rsi                         
    
    lea rbx, [rel jump_table]
    movsxd rcx, dword [rbx + rax*4] 
    add rcx, rbx
    jmp rcx                         
    
; HANDLERS
V_NOP:
    jmp vm_loop

V_MOVZX8:
    pop rax
    movzx rax, al
    push rax
    jmp vm_loop

V_MOVSX8:
    pop rax
    movsx rax, al
    push rax
    jmp vm_loop

V_MOVZX16:
    pop rax
    movzx rax, ax
    push rax
    jmp vm_loop

V_MOVSX16:
    pop rax
    movsx rax, ax
    push rax
    jmp vm_loop

V_MOVZX32:
    pop rax
    mov eax, eax
    push rax
    jmp vm_loop

V_MOVSX32:
    pop rax
    movsxd rax, eax
    push rax
    jmp vm_loop

V_PUSH_REG:
    movzx rax, byte [rsi]
    inc rsi
    mov rax, [rbp + rax*8]
    push rax                    
    jmp vm_loop

V_PUSH_IMM:
    mov rax, [rsi]
    add rsi, 8
    push rax
    jmp vm_loop

V_PUSH_IMM_RVA:
    mov rax, [rsi]                    
    add rsi, 8                        
    add rax, [rel current_image_base] 
    push rax                          
    jmp vm_loop

V_POP_REG:
    movzx rax, byte [rsi]
    inc rsi
    pop rbx
    mov [rbp + rax*8], rbx
    jmp vm_loop

V_READ_MEM8:
    pop rax
    movzx rbx, byte [rax]   
    push rbx
    jmp vm_loop

V_WRITE_MEM8:
    pop rbx                 
    pop rax                 
    mov byte [rbx], al      
    jmp vm_loop

V_READ_MEM16:
    pop rax
    movzx rbx, word [rax]   
    push rbx
    jmp vm_loop

V_WRITE_MEM16:
    pop rbx                 
    pop rax                 
    mov word [rbx], ax      
    jmp vm_loop

V_READ_MEM:
    pop rax                     
    mov rax, [rax]              
    push rax                    
    jmp vm_loop

V_WRITE_MEM:
    pop rbx                     
    pop rax                     
    mov [rbx], rax              
    jmp vm_loop

V_READ_MEM32:
    pop rax
    xor rbx, rbx
    mov ebx, dword [rax]    
    push rbx
    jmp vm_loop

V_WRITE_MEM32:
    pop rbx
    pop rax
    mov dword [rbx], eax    
    jmp vm_loop

; 64-BIT ALU
V_ADD:
    pop rbx                     
    pop rax                     
    add rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx       
    push rax
    jmp vm_loop

V_SUB:
    pop rbx
    pop rax
    sub rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    push rax
    jmp vm_loop

V_XOR:
    pop rbx
    pop rax
    xor rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    push rax
    jmp vm_loop

V_AND:
    pop rbx
    pop rax
    and rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    push rax
    jmp vm_loop

V_OR:
    pop rbx
    pop rax
    or rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    push rax
    jmp vm_loop

V_NOT:
    pop rax
    not rax
    push rax
    jmp vm_loop

V_MUL:
    pop rbx                     
    pop rax                     
    mul rbx                     
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    push rax                    
    jmp vm_loop

V_DIV:
    pop rbx                     
    pop rax                     
    xor rdx, rdx
    div rbx
    push rax                    
    jmp vm_loop

V_MOD:
    pop rbx                     
    pop rax                     
    xor rdx, rdx
    div rbx
    push rdx                    
    jmp vm_loop

V_SHL:
    pop rcx                     
    pop rax                     
    shl rax, cl
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    push rax
    jmp vm_loop

V_SHR:
    pop rcx
    pop rax
    shr rax, cl
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    push rax
    jmp vm_loop

V_SAR:
    pop rcx
    pop rax
    sar rax, cl
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    push rax
    jmp vm_loop

V_CMP:
    pop rbx
    pop rax
    cmp rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    jmp vm_loop

V_TEST:
    pop rbx
    pop rax
    test rax, rbx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    jmp vm_loop

; 32-BIT ALU
V_ADD32:
    pop rbx
    pop rax
    add eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx       
    mov eax, eax                
    push rax
    jmp vm_loop

V_SUB32:
    pop rbx
    pop rax
    sub eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    mov eax, eax
    push rax
    jmp vm_loop

V_XOR32:
    pop rbx
    pop rax
    xor eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    mov eax, eax
    push rax
    jmp vm_loop

V_AND32:
    pop rbx
    pop rax
    and eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    mov eax, eax
    push rax
    jmp vm_loop

V_OR32:
    pop rbx
    pop rax
    or eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    mov eax, eax
    push rax
    jmp vm_loop

V_NOT32:
    pop rax
    not eax
    mov eax, eax
    push rax
    jmp vm_loop

V_IMUL32:
    pop rbx
    pop rax
    imul eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    mov eax, eax
    push rax
    jmp vm_loop

V_DIV32:
    pop rbx
    pop rax
    xor rdx, rdx
    div ebx                     
    mov eax, eax                
    push rax
    jmp vm_loop

V_SHL32:
    pop rcx
    pop rax
    shl eax, cl
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    mov eax, eax
    push rax
    jmp vm_loop

V_SHR32:
    pop rcx
    pop rax
    shr eax, cl
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    mov eax, eax
    push rax
    jmp vm_loop

V_SAR32:
    pop rcx
    pop rax
    sar eax, cl                 
    pushfq
    pop rdx
    mov [rbp + 17*8], rdx
    mov eax, eax
    push rax
    jmp vm_loop

V_CDQ:
    mov eax, dword [rbp + 0*8]  
    cdq                         
    mov ebx, edx                
    mov [rbp + 2*8], rbx        
    jmp vm_loop

V_CMP32:
    pop rbx
    pop rax
    cmp eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    jmp vm_loop

V_TEST32:
    pop rbx
    pop rax
    test eax, ebx
    pushfq
    pop rcx
    mov [rbp + 17*8], rcx
    jmp vm_loop

; FLOW CONTROL
V_JMP:
    mov rbx, [rsi]              
    mov rsi, [rel bytecode_base]
    add rsi, rbx                
    jmp vm_loop

V_JCC:
    movzx rax, byte [rsi]       
    inc rsi
    mov rbx, [rsi]              
    add rsi, 8

    cmp al, 0x00
    je .L_JE
    cmp al, 0x01
    je .L_JNE
    cmp al, 0x02
    je .L_JA
    cmp al, 0x03
    je .L_JAE
    cmp al, 0x04
    je .L_JB
    cmp al, 0x05
    je .L_JBE
    cmp al, 0x06
    je .L_JG
    cmp al, 0x07
    je .L_JGE
    cmp al, 0x08
    je .L_JL
    cmp al, 0x09
    je .L_JLE
    cmp al, 0x0A
    je .L_JS
    cmp al, 0x0B
    je .L_JNS
    cmp al, 0x0C
    je .L_JP
    cmp al, 0x0D
    je .L_JNP
    cmp al, 0x0E
    je .L_JO
    cmp al, 0x0F
    je .L_JNO
    jmp vm_loop

    .L_JE:   
        push qword [rbp + 17*8]
        popfq
        je  .take_jmp 
        jmp vm_loop
    .L_JNE:  
        push qword [rbp + 17*8]
        popfq
        jne .take_jmp 
        jmp vm_loop
    .L_JA:   
        push qword [rbp + 17*8]
        popfq
        ja  .take_jmp 
        jmp vm_loop
    .L_JAE:  
        push qword [rbp + 17*8]
        popfq
        jae .take_jmp 
        jmp vm_loop
    .L_JB:   
        push qword [rbp + 17*8]
        popfq
        jb  .take_jmp 
        jmp vm_loop
    .L_JBE:  
        push qword [rbp + 17*8]
        popfq
        jbe .take_jmp 
        jmp vm_loop
    .L_JG:   
        push qword [rbp + 17*8]
        popfq
        jg  .take_jmp 
        jmp vm_loop
    .L_JGE:  
        push qword [rbp + 17*8]
        popfq
        jge .take_jmp 
        jmp vm_loop
    .L_JL:   
        push qword [rbp + 17*8]
        popfq
        jl  .take_jmp 
        jmp vm_loop
    .L_JLE:  
        push qword [rbp + 17*8]
        popfq
        jle .take_jmp 
        jmp vm_loop
    .L_JS:  
        push qword [rbp + 17*8]
        popfq
        js .take_jmp 
        jmp vm_loop
    .L_JNS:  
        push qword [rbp + 17*8]
        popfq
        jns .take_jmp 
        jmp vm_loop
    .L_JP:  
        push qword [rbp + 17*8]
        popfq
        jp .take_jmp 
        jmp vm_loop
    .L_JNP:  
        push qword [rbp + 17*8]
        popfq
        jnp .take_jmp 
        jmp vm_loop
    .L_JO:  
        push qword [rbp + 17*8]
        popfq
        jo .take_jmp 
        jmp vm_loop
    .L_JNO:  
        push qword [rbp + 17*8]
        popfq
        jno .take_jmp 
        jmp vm_loop

    .take_jmp:
        mov rsi, [rel bytecode_base] 
        add rsi, rbx                 
        jmp vm_loop

V_CALL_EXT_IND:
    mov r14, [rsi]                    
    add rsi, 8
    add r14, [rel current_image_base] 
    mov r14, [r14]                    
    jmp V_CALL_EXT.execute_call

V_CALL_EXT:
    mov r14, [rsi]                    
    add rsi, 8
    add r14, [rel current_image_base] 

.execute_call:
    mov [rbp + 16*8], rsi       

    mov rax, [rbp + 0*8]
    mov rcx, [rbp + 1*8]
    mov rdx, [rbp + 2*8]
    mov rbx, [rbp + 3*8]
    mov rsi, [rbp + 6*8]
    mov rdi, [rbp + 7*8]
    mov r8,  [rbp + 8*8]
    mov r9,  [rbp + 9*8]
    mov r10, [rbp + 10*8]
    mov r11, [rbp + 11*8]
    mov r12, [rbp + 12*8]
    mov r13, [rbp + 13*8]
    mov r15, [rbp + 15*8]

    mov [rel context_ptr], rbp
    mov rsp, [rbp + 4*8]        

    call r14                    

    mov rbp, [rel context_ptr]  

    mov [rbp + 0*8], rax        
    mov [rbp + 4*8], rsp        

    mov rsi, [rbp + 16*8]       
    jmp vm_loop

V_VMEXIT:
    movzx rcx, byte [rsi]       
    inc rsi
    lea rdi, [rel unhandled_stub]
    rep movsb                   
    
    mov byte [rdi], 0xE9        
    lea rax, [rel return_from_unhandled]
    sub rax, rdi
    sub rax, 5
    mov dword [rdi+1], eax

    mov [rbp + 16*8], rsi       

    mov rax, [rbp + 0*8]
    mov rcx, [rbp + 1*8]
    mov rdx, [rbp + 2*8]
    mov rbx, [rbp + 3*8]
    mov rsi, [rbp + 6*8]
    mov rdi, [rbp + 7*8]
    mov r8,  [rbp + 8*8]
    mov r9,  [rbp + 9*8]
    mov r10, [rbp + 10*8]
    mov r11, [rbp + 11*8]
    mov r12, [rbp + 12*8]
    mov r13, [rbp + 13*8]
    mov r14, [rbp + 14*8]
    mov r15, [rbp + 15*8]
    
    push qword [rbp + 17*8]
    popfq                       

    mov [rel context_ptr], rbp
    mov rbp, [rbp + 5*8]        
    
    mov rsp, [rel context_ptr]
    mov rsp, [rsp + 4*8]        

    jmp unhandled_stub

return_from_unhandled:
    mov [rel scratch_rsp], rsp
    mov rsp, [rel context_ptr] 

    mov [rsp + 0*8], rax
    mov [rsp + 1*8], rcx
    mov [rsp + 2*8], rdx
    mov [rsp + 3*8], rbx
    
    mov rax, [rel scratch_rsp]
    mov [rsp + 4*8], rax
    
    mov [rsp + 5*8], rbp
    mov [rsp + 6*8], rsi
    mov [rsp + 7*8], rdi
    mov [rsp + 8*8], r8
    mov [rsp + 9*8], r9
    mov [rsp + 10*8], r10
    mov [rsp + 11*8], r11
    mov [rsp + 12*8], r12
    mov [rsp + 13*8], r13
    mov [rsp + 14*8], r14
    mov [rsp + 15*8], r15
    
    pushfq
    pop rax
    mov [rsp + 17*8], rax       
    
    mov rbp, rsp
    mov rsp, rbp                
    
    mov rsi, [rbp + 16*8]       
    jmp vm_loop


V_EXIT:
    mov rax, [rsi]                    
    add rsi, 8
    add rax, [rel current_image_base] 
    mov [rel exit_target], rax  
    
    mov rax, [rbp + 0*8]
    mov rcx, [rbp + 1*8]
    mov rdx, [rbp + 2*8]
    mov rbx, [rbp + 3*8]
    mov rsi, [rbp + 6*8]
    mov rdi, [rbp + 7*8]
    mov r8,  [rbp + 8*8]
    mov r9,  [rbp + 9*8]
    mov r10, [rbp + 10*8]
    mov r11, [rbp + 11*8]
    mov r12, [rbp + 12*8]
    mov r13, [rbp + 13*8]
    mov r14, [rbp + 14*8]
    mov r15, [rbp + 15*8]
    
    push qword [rbp + 17*8]
    popfq
    
    mov rsp, [rbp + 4*8]        
    mov rbp, [rbp + 5*8]
    
    jmp qword [rel exit_target] 

unhandled_op:
    jmp vm_loop

; DATA & DYNAMIC MACROS
unhandled_stub:
    times 20 db 0x90
    
exit_target dq 0
context_ptr dq 0
scratch_rsp dq 0

current_image_base dq 0
bytecode_base dq 0

align 4
jump_table:
%assign i 0
%rep 256
    %if i == 0x00
        dd V_NOP - jump_table
    %elif i == 0x0A
        dd V_MOVZX8 - jump_table
    %elif i == 0x0B
        dd V_MOVSX8 - jump_table
    %elif i == 0x0C
        dd V_MOVZX16 - jump_table
    %elif i == 0x0D
        dd V_MOVSX16 - jump_table
    %elif i == 0x0E
        dd V_MOVZX32 - jump_table
    %elif i == 0x0F
        dd V_MOVSX32 - jump_table
    %elif i == 0x10
        dd V_PUSH_REG - jump_table
    %elif i == 0x11
        dd V_PUSH_IMM - jump_table
    %elif i == 0x12
        dd V_POP_REG - jump_table
    %elif i == 0x13
        dd V_PUSH_IMM_RVA - jump_table
    %elif i == 0x14
        dd V_READ_MEM8 - jump_table
    %elif i == 0x15
        dd V_WRITE_MEM8 - jump_table
    %elif i == 0x16
        dd V_READ_MEM16 - jump_table
    %elif i == 0x17
        dd V_WRITE_MEM16 - jump_table
    %elif i == 0x1A
        dd V_READ_MEM - jump_table
    %elif i == 0x1B
        dd V_WRITE_MEM - jump_table
    %elif i == 0x1C
        dd V_READ_MEM32 - jump_table
    %elif i == 0x1D
        dd V_WRITE_MEM32 - jump_table
    %elif i == 0x20
        dd V_ADD - jump_table
    %elif i == 0x21
        dd V_SUB - jump_table
    %elif i == 0x22
        dd V_XOR - jump_table
    %elif i == 0x23
        dd V_AND - jump_table
    %elif i == 0x24
        dd V_OR - jump_table
    %elif i == 0x25
        dd V_NOT - jump_table
    %elif i == 0x26
        dd V_MUL - jump_table
    %elif i == 0x27
        dd V_DIV - jump_table
    %elif i == 0x28
        dd V_MOD - jump_table
    %elif i == 0x30
        dd V_SHL - jump_table
    %elif i == 0x31
        dd V_SHR - jump_table
    %elif i == 0x32
        dd V_SAR - jump_table
    %elif i == 0x40
        dd V_CMP - jump_table
    %elif i == 0x41
        dd V_TEST - jump_table
    %elif i == 0x42
        dd V_CMP32 - jump_table
    %elif i == 0x43
        dd V_TEST32 - jump_table
    %elif i == 0x50
        dd V_JMP - jump_table
    %elif i == 0x51
        dd V_JCC - jump_table
    %elif i == 0x60
        dd V_ADD32 - jump_table
    %elif i == 0x61
        dd V_SUB32 - jump_table
    %elif i == 0x62
        dd V_XOR32 - jump_table
    %elif i == 0x63
        dd V_AND32 - jump_table
    %elif i == 0x64
        dd V_OR32 - jump_table
    %elif i == 0x65
        dd V_NOT32 - jump_table
    %elif i == 0x66
        dd V_IMUL32 - jump_table
    %elif i == 0x67
        dd V_DIV32 - jump_table
    %elif i == 0x68
        dd V_SHL32 - jump_table
    %elif i == 0x69
        dd V_SHR32 - jump_table
    %elif i == 0x6A
        dd V_SAR32 - jump_table
    %elif i == 0x6B
        dd V_CDQ - jump_table
    %elif i == 0xFC
        dd V_CALL_EXT_IND - jump_table
    %elif i == 0xFD
        dd V_CALL_EXT - jump_table
    %elif i == 0xFE
        dd V_VMEXIT - jump_table
    %elif i == 0xFF
        dd V_EXIT - jump_table
    %else
        dd unhandled_op - jump_table
    %endif
    %assign i i+1
%endrep