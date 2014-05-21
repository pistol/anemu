#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    printf("Hello World!\n");

    uint32_t Rd, Rn, Rm, cpsr, cpsr_old;
    Rd = 0;
    Rn = 0xfffffc1f;
    Rm = 0x815cc000;

    asm volatile("mrs %[cpsr_old], cpsr\n"
                 "subs %[Rm], %[Rn], %[Rm], asr #21\n"
                 "mrs %[cpsr], cpsr\n"
                 : [cpsr_old] "=r" (cpsr_old), [cpsr] "=r" (cpsr), [Rm] "+r" (Rm)
                 : [Rn] "r" (Rn)
                 : "cc"
                 );

    printf("Rd: %x\n", Rm);
    printf("cpsr_old: %x\n", cpsr_old);
    printf("cpsr_new: %x\n", cpsr);
    printf("\n");

    Rd = 0;
    Rn = Rm;
    Rm = 21;
    asm volatile("mrs %[cpsr_old], cpsr\n"
                 "asr %[Rd], %[Rn], %[Rm]\n"
                 "mrs %[cpsr], cpsr\n"
                 : [cpsr_old] "+r" (cpsr_old), [Rd] "=r" (Rd), [cpsr] "=&r" (cpsr)
                 : [Rn] "r" (Rn), [Rm] "r" (Rm)
                 : "cc"
                 );

    printf("Rd: %x\n", Rd);
    printf("cpsr_old: %x\n", cpsr_old);
    printf("cpsr_new: %x\n", cpsr);
    printf("\n");

    Rn = 0xfffffc1f;
    Rm = Rd;
    Rd = 0;
    asm volatile("mrs %[cpsr_old], cpsr\n"
                 "asr %[Rd], %[Rn], %[Rm]\n"
                 "mrs %[cpsr], cpsr\n"
                 : [cpsr_old] "+r" (cpsr_old), [Rd] "=r" (Rd), [cpsr] "=&r" (cpsr)
                 : [Rn] "r" (Rn), [Rm] "r" (Rm)
                 : "cc"
                 );

    printf("Rd: %x\n", Rd);
    printf("cpsr_old: %x\n", cpsr_old);
    printf("cpsr_new: %x\n", cpsr);

    return 0;
}
