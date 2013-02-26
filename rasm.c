/* rasm2 disassembler */
#include <r_asm.h>
#include <assert.h>

static struct r_asm_t *rasm;    /* rasm2 disassembler */

void rasm_init(const char *arch, const int bits, const int big_endian) {
    rasm = r_asm_new();
    assert(rasm != NULL);
    /* R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian); */
    r_asm_setup(rasm, arch, bits, big_endian);
}

/* reference (accurate but expensive) disassembly */
const char* emu_disas_ref(unsigned int pc) {
    if (!rasm) {
        /* rasm2 configuration defaults */
        static const char arch[]    = {"arm"};   /* ARM ISA */
        static const int bits       = 32;        /* A32 instructions only */
        static const int big_endian = 0;         /* ARMv7 is little endian */

        rasm_init(arch, bits, big_endian);        
    }

    /* printf("emu: %0lx: %0x\n", cpu(pc), *(unsigned int *)cpu(pc)); // if all else fails */
    static RAsmOp rop;

    static const int len = 4;         /* disassemble 4 bytes (A32) */
    r_asm_set_pc(rasm, pc);
    r_asm_disassemble(rasm, &rop, (const unsigned char *)pc, len);
    printf("disas: %x %08x %s\n", pc, *(const unsigned int *)pc, rop.buf_asm);

    return rop.buf_asm;
}
