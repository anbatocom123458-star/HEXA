# HEXA x86-64 libc-free runtime (raw Linux syscalls).
# Syscall numbers (x86_64): 0=read 1=write 9=mmap 11=munmap 60=exit.

    .text
    .globl _start
    .type _start, @function
_start:
    xorl %ebp, %ebp
    andq $-16, %rsp
    call hexa_main
    movl %eax, %edi
    movl $60, %eax
    syscall
    hlt

# hexa_write(fd=rdi, buf=rsi, n=rdx)  -> clobbers rax,rcx,r11
    .globl hexa_write
    .type hexa_write, @function
hexa_write:
    movl $1, %eax
    syscall
    ret

# hexa_exit(code=rdi)
    .globl hexa_exit
    .type hexa_exit, @function
hexa_exit:
    movl $60, %eax
    syscall
    hlt

# hexa_alloc(size=rdi) -> rax = pointer (anonymous mmap)
    .globl hexa_alloc
    .type hexa_alloc, @function
hexa_alloc:
    movq $9, %rax
    xorl %edi, %edi
    movq %rdi, %rsi
    movq $3, %rdx
    movq $34, %r10
    movq $-1, %r8
    xorq %r9, %r9
    syscall
    ret

# hexa_memcpy(dst=rdi, src=rsi, n=rdx)
    .globl hexa_memcpy
    .type hexa_memcpy, @function
hexa_memcpy:
    xorq %rcx, %rcx
.Lhexa_memcpy_loop:
    cmpq %rdx, %rcx
    jae .Lhexa_memcpy_end
    movb (%rsi,%rcx), %al
    movb %al, (%rdi,%rcx)
    incq %rcx
    jmp .Lhexa_memcpy_loop
.Lhexa_memcpy_end:
    ret

# hexa_concat_text(a=rdi, b=rsi) -> rax = new value{len,data}
    .globl hexa_concat_text
    .type hexa_concat_text, @function
hexa_concat_text:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rdi, %r12
    movq %rsi, %r13
    movq (%r12), %r14
    movq (%r13), %r15
    movq %r14, %rax
    addq %r15, %rax
    addq $8, %rax
    movq %rax, %rdi
    call hexa_alloc
    movq %rax, %rbx
    movq %r14, %rax
    addq %r15, %rax
    movq %rax, (%rbx)
    # copy a
    leaq 8(%rbx), %rdi
    leaq 8(%r12), %rsi
    movq %r14, %rdx
    call hexa_memcpy
    # copy b
    leaq 8(%rbx), %rdi
    addq %r14, %rdi
    leaq 8(%r13), %rsi
    movq %r15, %rdx
    call hexa_memcpy
    movq %rbx, %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

# hexa_itoa_str(val=rdi) -> (rsi=ptr, rdx=len) into shared buffer
    .globl hexa_itoa_str
    .type hexa_itoa_str, @function
hexa_itoa_str:
    pushq %rbp
    movq %rsp, %rbp
    leaq hexa_itoa_buf+31(%rip), %rsi
    movq %rdi, %rax
    xorl %r9d, %r9d
    testq %rax, %rax
    jns .Litoa_pos
    movl $1, %r9d
    negq %rax
.Litoa_pos:
    movq $10, %r8
.Litoa_loop:
    xorl %edx, %edx
    divq %r8
    addb $48, %dl
    decq %rsi
    movb %dl, (%rsi)
    testq %rax, %rax
    jnz .Litoa_loop
    testl $1, %r9d
    jz .Litoa_done
    decq %rsi
    movb $45, (%rsi)
.Litoa_done:
    leaq hexa_itoa_buf+31(%rip), %rdx
    subq %rsi, %rdx
    incq %rdx
    popq %rbp
    ret

# hexa_print_str(ptr=rdi): write text value then newline
    .globl hexa_print_str
    .type hexa_print_str, @function
hexa_print_str:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, %rsi
    addq $8, %rsi
    movq (%rdi), %rdx
    movl $1, %edi
    call hexa_write
    leaq hexa_newline(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq %rbp, %rsp
    popq %rbp
    ret

# hexa_print_int(val=rdi)
    .globl hexa_print_int
    .type hexa_print_int, @function
hexa_print_int:
    pushq %rbp
    movq %rsp, %rbp
    call hexa_itoa_str
    movq %rsi, %rsi
    movq %rdx, %rdx
    movl $1, %edi
    call hexa_write
    leaq hexa_newline(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq %rbp, %rsp
    popq %rbp
    ret

# hexa_print_bool(val=rdi 0/1)
    .globl hexa_print_bool
    .type hexa_print_bool, @function
hexa_print_bool:
    pushq %rbp
    movq %rsp, %rbp
    testq %rdi, %rdi
    jz .Lbool_false
    leaq hexa_str_true(%rip), %rsi
    movl $4, %edx
    jmp .Lbool_write
.Lbool_false:
    leaq hexa_str_false(%rip), %rsi
    movl $5, %edx
.Lbool_write:
    movl $1, %edi
    call hexa_write
    leaq hexa_newline(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq %rbp, %rsp
    popq %rbp
    ret

# hexa_print_dec(bits=rdi): integer part, '.', fraction digits (up to 6)
    .globl hexa_print_dec
    .type hexa_print_dec, @function
hexa_print_dec:
    pushq %rbp
    movq %rsp, %rbp
    subq $40, %rsp
    movq %rdi, 8(%rsp)
    movq %rdi, %xmm0
    cvttsd2si %xmm0, %rax
    movq %rax, 24(%rsp)
    movq %rax, %rdi
    call hexa_itoa_str
    movq %rsi, %rsi
    movq %rdx, %rdx
    movl $1, %edi
    call hexa_write
    leaq hexa_dot(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq 8(%rsp), %xmm2
    movq 24(%rsp), %rax
    cvtsi2sd %rax, %xmm1
    subsd %xmm1, %xmm2
    movl $0, 16(%rsp)
    movl $1091567616, 20(%rsp)
    movq 16(%rsp), %xmm3
    mulsd %xmm3, %xmm2
    cvttsd2si %xmm2, %rax
    movq %rax, %rdi
    call hexa_itoa_str
    movq %rsi, %rsi
    movq %rdx, %rdx
    movl $1, %edi
    call hexa_write
    leaq hexa_newline(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq %rbp, %rsp
    popq %rbp
    ret

    .section .rodata
    .align 8
hexa_newline: .byte 10
hexa_dot: .byte 46
hexa_str_true: .ascii "true"
hexa_str_false: .ascii "false"

    .section .bss
    .align 8
hexa_itoa_buf: .skip 32
