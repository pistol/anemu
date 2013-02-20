.text
.global test_asm
.balign 0x1000,0x0

test_asm:
        bkpt 0x1
        add  r0, r1, #8
        sub  r0, r0, #4
        movt r0, #0xdead
        mov  r0, r0             ; nop
        add  r0, r0, #2
        movw r1, #0x1337
        adc  r0, r1, r2, lsl #1
        bkpt 0x2
        mov  pc, lr
