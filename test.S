.data
        TEMP = 0x8
.text
.global test_asm
.balign 0x1000,0x0

test_asm:
        @ emu start trigger
        bkpt 0x1
        @ clear registers
        mov  r0, #0
        mov  r1, #0
        mov  r2, #0
        mov  r3, #0
        mov  r4, #0
        mov  r5, #0
        mov  r6, #0
        mov  r7, #0
        mov  r8, #0
        mov  r9, #0
        mov  r10, #0
        eor  r0, r0, r0
        add  r0, #TEMP
        @ condition code test
        mov r0, #8
        mov r1, #4
        cmp r0, r1
        bgt exit
        mov r0, r1
        bal exit
        @ stack manipulation
        stmfd  sp!, {fp, ip, lr, pc} @ push
        @ test loads and stores
        ldr  r1, =a
        ldr  r2, [r1]
        ldr  r3, [r1, #4]
        str  r5, [sp, #-4]!
        ldr  r5, [sp], #4
        @ mov variations
        mov  r1, #0x1000
        add  r0, r1, #8
        sub  r0, r0, #4
        movt r0, #0xdead
        mov  r0, r0
        add  r0, r0, #2
        movw r1, #0x1337
        @ shifters
        adc  r0, r1, r2, lsl #1

exit:   bkpt 0x2
        mov  pc, lr

a:      .word 0xdeadbeef        @ data for loads/stores
b:      .word 0xbadcab1e
c:      .word 0

        .end
