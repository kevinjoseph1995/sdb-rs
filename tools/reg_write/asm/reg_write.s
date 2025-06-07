.global main

.section .data

hex_format: .asciz "%#x"
float_format: .asciz "%.2f"
long_float_format: .asciz "%.2Lf"

.section .text

.macro trap
    # 62 is the syscall ID for kill
    movq $62, %rax
    # Set rdi to the PID we just got
    movq %r12, %rdi
    # The signal ID for SIGTRAP is 5
    movq $5, %rsi
    syscall
.endm

main:
    # Setup the stack frame
    push %rbp
    movq %rsp, %rbp # Save the base pointer

    # Get PID of the current process. 39 is the syscall ID for getpid
    movq $39, %rax
    syscall
    # Store the PID in r12
    movq %rax, %r12

    trap

    leaq hex_format(%rip), %rdi
    movq $0, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Move the contents of mm0 to rsi
    movq %mm0, %rsi
    leaq hex_format(%rip), %rdi
    movq $0, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Print contents of xmm0
    leaq float_format(%rip), %rdi
    movq $1, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Print contents of st0
    subq $16, %rsp
    fstpt (%rsp) # Store st0 on the stack
    leaq long_float_format(%rip), %rdi
    movq $0, %rax # Prepare for printf
    call printf@plt # Print long double Because a long double is 16 bytes and variadic, GCC passes it only on the stack. The call site has already placed it at the correct stack address (%rsp).
    movq $0, %rdi
    call fflush@plt
    addq $16, %rsp
    trap

    popq %rbp
    # Return value
    movq $0, %rax
    ret
