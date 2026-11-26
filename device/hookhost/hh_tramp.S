/* hh_tramp.S - AArch64 detour trampolines.
 *
 * FS's executor uses the normal AAPCS64 convention: x0..x7 are arguments and
 * the 9th argument ("mode", a byte) is on the stack. Callees may clobber
 * x0..x18; x19..x28, x29 and x30 must survive. We only need to preserve
 * x29/x30 across the C call and forward the stack argument.
 *
 * The callers store mode with STRB into an uninitialised slot and the
 * executor reads it with LDRB (FS 23.5.0 0x18A6B0 / 0x18C3D0), so bytes 1..7
 * of the slot are stack garbage: load the byte only. A 64-bit load made reads
 * look like mode != 2, so they were never sealed (2002-2655).
 */
    .section .text.hh_tramp, "ax", %progbits

    .global hh_exec_tramp
    .type   hh_exec_tramp, %function
hh_exec_tramp:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    ldrb    w7, [sp, #16]        /* mode: caller's stack byte, x7 replaced */
    bl      hh_exec_c
    ldp     x29, x30, [sp], #16
    ret
    .size   hh_exec_tramp, .-hh_exec_tramp

    .global hh_presence_tramp
    .type   hh_presence_tramp, %function
hh_presence_tramp:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      hh_presence_c
    ldp     x29, x30, [sp], #16
    ret
    .size   hh_presence_tramp, .-hh_presence_tramp

/* Called from FS crt0 in place of the bss memset. x0=bss, x1=0, x2=size.
 * Runs the hook host with the crt0 return address, then performs the memset. */
    .global hh_entry_tramp
    .type   hh_entry_tramp, %function
hh_entry_tramp:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    mov     x0, x30
    bl      hh_entry_c
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
    bl      memset
    ldp     x29, x30, [sp], #16
    ret
    .size   hh_entry_tramp, .-hh_entry_tramp
