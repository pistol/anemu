        .text
        .arch   armv7-a
        .align  2
        .global test_asm
        .type   test_asm, %function
        .balign 0x1000,0x0

test_asm:
        @ emu start trigger
        bkpt 0x1
        @ save regs
        @ r4-r8  callee-save
        @ r9     callee-save/special
        @ r0-r11 callee-save
        push {r4-r11}
        @ arg registers
        mov  a1, #0
        mov  a2, #0
        mov  a3, #0
        mov  a4, #0
        @ var regs
        mov  v1, #0
        mov  v2, #0
        mov  v3, #0
        mov  v4, #0
        mov  v5, #0
        mov  v6, #0
        mov  v7, #0
        @ mov  v8, #0
        eor  r0, r0, r0
        @ mov variations
        mov  r1, #0x1000
        add  r0, r1, #8
        sub  r0, r0, #4
        movt r0, #0xdead
        mov  r0, r0
        add  r0, r0, #2
        movw r1, #0x1337
        @ condition code test
        mov r0, #2
        mov r1, #4
        cmp r0, r1
        movgt r0, #0x13
        bgt exit
        @ test loads and stores
        ldr  r1, =foo
        ldr  r2, [r1]
        ldr  r3, [r1, #4]
        str  r3, [r1]
        @ stack manipulation
        stmfd  sp!, {fp, ip, lr, pc} @ push
        push {r0-r3, r5}
        mov r0, #0
        mov r1, #0
        mov r2, #0
        mov r3, #0
        mov r5, #0
        pop {r0-r3, r5}
        pop {r0-r4}
        @ flags
        movs r0, #0x8000
        ldr r0, =bar
        ldr r1, [r0]
        subs r0, r1, #0x1000
        adc  r0, r0, #0x1000
        adcs r0, r0, #0x8
        movs r0, #0x2000
        movs r0, #0xf0000000
        movs r0, #0
        mov  r0, #0x0e00
        orrs  r0, r0, #0xf100
        ands  r0,  r0, #0
        @ shifters
        mov  r0, #4
        mov  r1, #2
        add  r3, r0, r1, lsl #5
        mov  r3, #2
        add  r4, r0, r1, ror r3
        @ restore all callee-save regs
        pop {r4-r11}
        movw r0, #0x1337

exit:   bkpt 0x2                @ emu stop trigger
        mov  pc, lr

        .size test_asm, .-test_asm

        .data
foo:      .word 0xbadcab1e        @ data for loads/stores
bar:      .word 0xdeadbeef
        .end
