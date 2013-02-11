.text
.global test
.balign 0x1000,0x0

test:
        bkpt 0x1
        add  r0, r0, #1
        movt r0, #0xdead
        mov  r0, r0             ; nop
        add  r0, r0, #2
        movw r1, #0x1337
        bkpt 0x2
        mov  pc, lr
