/* rasm2 disassembler */
#include <r_asm.h>
#include <assert.h>

static struct r_asm_t *rasm;    /* rasm2 disassembler */


/* reference (accurate but expensive) disassembly */
const char* emu_disas_ref(unsigned int pc, uint8_t bits) {
    if (!rasm) {
        /* rasm2 configuration defaults */
        static const char arch[]    = {"arm"};   /* ARM ISA */
        static const int big_endian = 0;         /* ARMv7 is little endian */

        rasm = r_asm_new();
        /* R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian); */
        r_asm_setup(rasm, arch, bits, big_endian);
    }
    assert(rasm != NULL);

    r_asm_set_bits(rasm, bits);
    r_asm_set_big_endian(rasm, bits == 16); /* 16: big endian, 32: little endian */

    /* printf("emu: %0lx: %0x\n", cpu(pc), *(unsigned int *)cpu(pc)); // if all else fails */
    static RAsmOp rop;

    const int len = bits / 8;         /* disassemble 4 bytes (A32) or 2 bytes (T16) */
    uint32_t ins = *(const uint32_t *)pc;
    if (bits == 16) ins &= 0xffff;

    r_asm_set_pc(rasm, pc);
    r_asm_disassemble(rasm, &rop, (const unsigned char *)pc, len);
    printf("disas: %x %x %s\n", pc, ins, rop.buf_asm);

    return rop.buf_asm;
}
