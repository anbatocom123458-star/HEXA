# HEXA x86-64 runtime (Linux).
#
# The executable is linked dynamically against libc so that HEXA-compiled
# programs can load the shared runtime library (libhexa_runtime.so) via
# dlopen(3)/dlsym(3). The entry point follows the standard libc handoff:
# _start -> __libc_start_main(hexa_c_main) -> hexa_rt_ensure_ns -> hexa_main.
# Program code itself still performs I/O through raw syscalls below.
# Syscall numbers (x86_64): 0=read 1=write 9=mmap 11=munmap 60=exit.

    .text
    .globl _start
    .type _start, @function
_start:
    xorl %ebp, %ebp
    movq %rsp, %r15                 # original stack (argc, argv, envp)
    andq $-16, %rsp
    pushq $0                        # stack_end placeholder (arg 7 slot)
    pushq %r15                      # 7th arg: stack_end
    xorl %ecx, %ecx                 # init = NULL
    xorl %r8d, %r8d                 # fini = NULL
    xorl %r9d, %r9d                 # rtld_fini = NULL
    movq (%r15), %rsi               # argc
    leaq 8(%r15), %rdx              # argv
    leaq hexa_c_main(%rip), %rdi    # main
    call __libc_start_main@PLT
    hlt

# hexa_c_main: bootstrap the runtime library, run the program, exit.
    .type hexa_c_main, @function
hexa_c_main:
    pushq %rbp
    movq %rsp, %rbp
    call hexa_rt_ensure_ns
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
    # mmap(addr=0, length=rdi, prot=RW, flags=ANON|PRIVATE, fd=-1, off=0)
    movq %rdi, %rsi     # length (save BEFORE addr is zeroed)
    movq $9, %rax       # mmap
    xorl %edi, %edi     # addr = NULL
    movq $3, %rdx       # prot = PROT_READ|PROT_WRITE
    movq $34, %r10      # flags = MAP_PRIVATE|MAP_ANONYMOUS
    movq $-1, %r8       # fd
    xorq %r9, %r9       # offset
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
    # length = (buf+31) - rsi: count of written bytes (no trailing fill).
    # rsi is an absolute address; the original +1 included the unused
    # terminator byte and made every print gain a trailing NUL.
    leaq hexa_itoa_buf+31(%rip), %rdx
    subq %rsi, %rdx
    popq %rbp
    ret

# hexa_print_str(ptr=rdi): write text value then newline
    .globl hexa_print_str
    .type hexa_print_str, @function
hexa_print_str:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movq %rdi, -8(%rbp)
    call hexa_rt_ensure_ns
    movq hexa_fn_print(%rip), %r11
    testq %r11, %r11
    jz .Lps_fallback
    movq hexa_rt_handle(%rip), %rdi
    movq -8(%rbp), %rsi
    call *%r11
    testq %rax, %rax
    js .Lps_rt_fail
    jmp .Lps_nl
.Lps_fallback:
    # Literal values still have the {len,data} layout, so a raw write is
    # possible without the runtime library; non-literal values are not,
    # and fail honestly below.
    movq -8(%rbp), %rsi
    testq %rsi, %rsi
    jz .Lps_rt_fail
    movq (%rsi), %rdx
    addq $8, %rsi
    movl $1, %edi
    call hexa_write
    jmp .Lps_nl
.Lps_nl:
    leaq hexa_newline(%rip), %rsi
    movl $1, %edi
    movl $1, %edx
    call hexa_write
    movq %rbp, %rsp
    popq %rbp
    ret
.Lps_rt_fail:
    # The runtime library is required for this output and is not usable.
    movl $70, %edi
    call hexa_exit

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
    # fraction digits = frac * 1e6 (double bits of 1000000.0)
    movq $0x412E848000000000, %rax
    movq %rax, %xmm3
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

# ============================================================ #
# Runtime library bridge (Phase: packaging/runtime)
#
# Native executables produced by `hexa build` are linked against a
# shared runtime library (libhexa_runtime.so, built from the crypto
# subsystem) that provides the crypto, filesystem, and encoding
# primitives of the HEXA standard library over a versioned C ABI.
#
# The library is resolved at process start via dlopen(3)/dlsym(3)
# using libc (the same technique ld.so itself uses to bootstrap).
# Symbols are weak references: if the library is missing, the
# executable still runs std-free programs and fails honestly
# (exit 70) on operations that require the runtime.
# ============================================================ #

    .bss
    .align 8
hexa_rt_handle: .skip 8
hexa_rt_checked: .skip 8
hexa_fn_init: .skip 8
hexa_fn_print: .skip 8
hexa_fn_write_file: .skip 8
hexa_fn_read_file: .skip 8
hexa_fn_encrypt_file: .skip 8
hexa_fn_decrypt_file: .skip 8
hexa_fn_hash: .skip 8
hexa_fn_random: .skip 8
hexa_fn_key_display: .skip 8
hexa_fn_hex_encode: .skip 8
hexa_fn_hex_decode: .skip 8
hexa_fn_to_text: .skip 8
hexa_fn_alloc: .skip 8
hexa_fn_free: .skip 8
hexa_fn_last_error: .skip 8

    .text
# ---- hexa_rt_ensure_ns: one-time runtime bootstrap (non-reentrant) ----
# Preserves all caller registers except rax/r11/rcx.
    .globl hexa_rt_ensure_ns
    .type hexa_rt_ensure_ns, @function
hexa_rt_ensure_ns:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    cmpq $0, hexa_rt_checked(%rip)
    jne .Lren_already
    movq $1, hexa_rt_checked(%rip)
    # -- step 1: dlopen("libhexa_runtime.so", RTLD_NOW)
    leaq hexa_s_libhexa(%rip), %rdi
    movq $2, %rsi                   # RTLD_NOW
    call dlopen@PLT
    testq %rax, %rax
    jz .Lren_fail
    movq %rax, hexa_rt_handle(%rip)
    movq %rax, %r15                 # runtime handle
    # -- step 2: dlsym the ABI entry points
    xorl %ebx, %ebx                 # symbol index
.Lren_sym_loop:
    leaq hexa_sym_table(%rip), %rax
    leaq (%rax,%rbx,8), %rax
    movq (%rax), %rsi               # symbol name
    testq %rsi, %rsi
    jz .Lren_syms_done
    movq %r15, %rdi
    call dlsym@PLT
    leaq hexa_fn_table(%rip), %rcx
    leaq (%rcx,%rbx,8), %rcx
    movq %rax, (%rcx)
    incq %rbx
    jmp .Lren_sym_loop
.Lren_syms_done:
    # -- step 3: ABI handshake
    movq hexa_fn_init(%rip), %r11
    testq %r11, %r11
    jz .Lren_fail
    movq $1, %rdi                   # HEXA_RT_ABI_VERSION = 1
    call *%r11
    testq %rax, %rax
    jnz .Lren_fail
    jmp .Lren_already
.Lren_fail:
    xorl %eax, %eax
    movq %rax, hexa_rt_handle(%rip)
    movq %rax, hexa_fn_init(%rip)
.Lren_already:
    # The early-exit path (runtime already initialized) and the bootstrap
    # path must unwind the SAME prologue: five saved registers plus the
    # alignment slot. A previous version jumped from the early-exit test
    # straight to `popq %rbp`, skipping the five register pops, so the
    # final `ret` read a saved register as the return address and jumped
    # into unmapped memory (SEGV before any program output).
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

    .section .rodata
hexa_s_libhexa:     .asciz "libhexa_runtime.so"

    .align 8
hexa_sym_table:
    .quad hexa_s_init
    .quad hexa_s_print
    .quad hexa_s_write_file
    .quad hexa_s_read_file
    .quad hexa_s_encrypt_file
    .quad hexa_s_decrypt_file
    .quad hexa_s_hash
    .quad hexa_s_random
    .quad hexa_s_key_display
    .quad hexa_s_hex_encode
    .quad hexa_s_hex_decode
    .quad hexa_s_to_text
    .quad hexa_s_alloc
    .quad hexa_s_free
    .quad hexa_s_last_error
    .quad 0
hexa_fn_table:
    .quad hexa_fn_init
    .quad hexa_fn_print
    .quad hexa_fn_write_file
    .quad hexa_fn_read_file
    .quad hexa_fn_encrypt_file
    .quad hexa_fn_decrypt_file
    .quad hexa_fn_hash
    .quad hexa_fn_random
    .quad hexa_fn_key_display
    .quad hexa_fn_hex_encode
    .quad hexa_fn_hex_decode
    .quad hexa_fn_to_text
    .quad hexa_fn_alloc
    .quad hexa_fn_free
    .quad hexa_fn_last_error

hexa_s_init:        .asciz "hexa_sys_init"
hexa_s_print:       .asciz "hexa_fs_print"
hexa_s_write_file:  .asciz "hexa_fs_write_file"
hexa_s_read_file:   .asciz "hexa_fs_read_file"
hexa_s_encrypt_file: .asciz "hexa_crypto_encrypt_file"
hexa_s_decrypt_file: .asciz "hexa_crypto_decrypt_file"
hexa_s_hash:        .asciz "hexa_crypto_hash"
hexa_s_random:      .asciz "hexa_sys_random"
hexa_s_key_display: .asciz "hexa_crypto_key_display"
hexa_s_hex_encode:  .asciz "hexa_encoding_hex_encode"
hexa_s_hex_decode:  .asciz "hexa_encoding_hex_decode"
hexa_s_to_text:     .asciz "hexa_fs_to_text"
hexa_s_alloc:       .asciz "hexa_rt_alloc"
hexa_s_free:        .asciz "hexa_rt_free"
hexa_s_last_error:  .asciz "hexa_rt_last_error"

