#include "anemu.h"
#include <assert.h>

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

int main(int argc, char ** argv) {
    emu_register_handler(&emu_handler);
    execute_instr();

    return 0;
}

/* int __attribute__((aligned(0x1000))) execute_instr() */
/* Simulate a native binary executing */
int execute_instr() {
    int val = 0x1337;

    int ret = test_asm(val);
    emu_printf("ret: %x\n", ret);

    emu_printf("finished\n");

    return ret;
}

int test_c(int arg) {
    int ret = test_asm(arg);
    emu_printf("ret: %x\n", ret);
        
    return ret;
}

int emu_regs_clean() {
    return 0;                   /* TODO */
}

/* SIGTRAP handler used for single-stepping */
void emu_handler(int sig, siginfo_t *si, void *ucontext) {
    emu_printf("SIG %d with TRAP code: %d pc: 0x%lx addr: 0x%x\n",
           sig, 
           si->si_code, 
           (*(ucontext_t *)ucontext).uc_mcontext.arm_pc, 
           (int) si->si_addr);

    emu_init();                 /* one time emu state initialization */
    emu_start((ucontext_t *)ucontext);
    emu_stop();
}

void emu_init() {
    if (emu.initialized == 1) return;

    emu_printf("initializing rasm2 diassembler ...\n");

    /* rasm2 configuration defaults */
    static const char arch[]    = {"arm"};   /* ARM ISA */
    static const int bits       = 32;        /* A32 instructions only */
    static const int big_endian = 0;         /* ARMv7 is little endian */

    rasm = r_asm_new();
    assert(rasm != NULL);
    /* R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian); */
    r_asm_setup(rasm, arch, bits, big_endian);

    /* init darm */
    emu_printf("initializing darm diassembler ...\n");
    darm = malloc(sizeof(darm_t));

    emu.initialized = 1;
    emu_printf("finished\n");
}

uint8_t emu_eval_cond(uint32_t cond) {
    emu_printf("cpsr N: %d, Z: %d, C: %d, V: %d\n", cpsr.N, cpsr.Z, cpsr.C, cpsr.V);

    switch(cond) {
    case C_EQ: return (  cpsr.Z == 1);
    case C_NE: return (  cpsr.Z == 0);
    case C_CS: return (  cpsr.C == 1);
    case C_CC: return (  cpsr.C == 0);
    case C_MI: return (  cpsr.N == 1);
    case C_PL: return (  cpsr.N == 0);
    case C_VS: return (  cpsr.V == 1);
    case C_VC: return (  cpsr.V == 0);
    case C_HI: return (( cpsr.C == 1) && (cpsr.Z == 0));
    case C_LS: return (( cpsr.C == 0) && (cpsr.Z == 1));
    case C_GE: return (  cpsr.N == cpsr.V);
    case C_LT: return (  cpsr.N != cpsr.V);
    case C_GT: return (( cpsr.Z == 0) && (cpsr.N == cpsr.V));
    case C_LE: return (( cpsr.Z == 1) && (cpsr.N != cpsr.V));
    case C_AL: return 1;
    case C_UNCOND: return 1;
    default: {
        emu_printf("unknown condition %x\n", cond);
        return 0;
    }
    }
}

void emu_type_arith_shift(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_ADD:
    case I_ADC:
    case I_SUB: {
        // emu_op_alu(d);
        break;
    }
    case I_EOR: {
        REG(d->Rd) = REG(d->Rn) ^ REG(d->Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_arith_imm(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_ADD: {
        EMU(Rd, Rn, +, imm);
        break;
    }
    case I_ADC: {
        REG(d->Rd) = REG(d->Rn) + d->imm + cpsr.C;
        break;
    }
    case I_SUB: {
        EMU(Rd, Rn, -, imm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_branch_syscall(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_B: {
        if (emu_eval_cond(d->cond)) {
            cpu(pc) += d->imm + 4;
        }
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_branch_misc(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_BKPT: {
        /* ignore */
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_move_imm(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_MOV: {
        REG(d->Rd) = d->imm;
        break;
    }
    case I_MOVT: {
        REG(d->Rd) = (REG(d->Rd) & 0x0000ffff) | (d->imm << 16);
        break;
    }
    case I_MOVW: {
        REG(d->Rd) = (REG(d->Rd) & 0xffff0000) | (d->imm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_cmp_op(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_CMP: {
        asm volatile (
             "cmp %[a], %[b]\n\t"                         /* updates flags */
             "mrs %[ps], CPSR\n\t"                        /* save new cpsr */
             : [ps] "=r" (cpu(cpsr))                      /* output */
             : [a] "r" (REG(d->Rn)), [b] "r" (REG(d->Rm)) /* input */
             : "cc"                                       /* clobbers condition codes */
             );
        CPSR_UPDATE_BITS;
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_cmp_imm(const darm_t * d) {
    emu_printf("not implemented\n");
}

void emu_type_opless(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_NOP: {
        /* nothing to do */
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_dst_src(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_MOV: {
        REG(d->Rd) = REG(d->Rm);
        break;
    }
    case I_NOP: {
        /* nothing to do */
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_memory(const darm_t * d) {
    /* EMU_ENTRY; */

    switch((uint32_t) d->instr) {
    case I_LDR: {
        uint32_t offset_addr = d->U ?
            (RREG(Rn) + d->imm) :
            (RREG(Rn) - d->imm);

        uint32_t addr = d->P ?
            offset_addr :
            RREG(Rn);

        if ((d->W == 1) || (d->P == 0)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

        emu_printf("addr: %x\n", addr);
        EMU(WREG(Rt) = *(uint32_t *)(addr));
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_start(ucontext_t *ucontext) {
    emu_printf("saving original ucontext ...\n");
    emu.previous = emu.current = emu.original = *ucontext;
    emu_dump();
    emu_printf("starting emulation ...\n\n");
    
    static const char *assembly;
    static const darm_t *d;
    while(1) {
        CPU(pc) += 4;
        emu_dump_diff();
        printf("\n");
        // TODO: check if Thumb mode

        // 1. decode instr
        assembly = emu_disas(CPU(pc)); /* rasm2 with libopcodes backend */
        d = emu_darm(CPU(pc));         /* darm */
        darm_dump(d);                  /* dump internal darm_t state */

        if (!emu_eval_cond(d->cond)) continue;

        if (emu_stop_trigger(assembly)) break;

        // 2. emu instr by type
        switch(d->instr_type) {
        case T_ARITH_SHIFT: {
            emu_type_arith_shift(d);
            break;
        }
        case T_ARITH_IMM: {
            emu_type_arith_imm(d);
            break;
        }
        case T_BRNCHSC: {
            emu_type_branch_syscall(d);
            break;
        }
        case T_BRNCHMISC: {
            emu_type_branch_misc(d);
            break;
        }
        case T_MOV_IMM: {
            emu_type_move_imm(d);
            break;
        }
        case T_CMP_IMM: {
            emu_type_cmp_imm(d);
            break;
        }
        case T_CMP_OP: {
            emu_type_cmp_op(d);
            break;
        }
        case T_OPLESS: {
            emu_type_opless(d);
            break;
        }
        case T_DST_SRC: {
            emu_type_dst_src(d);
            break;
        }
        case T_STACK0:
        case T_STACK1:
        case T_STACK2:
        case T_LDSTREGS: {
            emu_type_memory(d);
            break;
        }
        case T_INVLD: {
            emu_printf("darm invalid type (unsupported yet)\n");
            break;
        }
        default:
            emu_printf("unhandled type %d\n", d->type);
        }
    }
    emu_printf("finished\n");
}

void emu_stop() {
    emu_printf("resuming exec pc old: 0x%0lx new: 0x%0lx\n",
           emu.original.uc_mcontext.arm_pc, 
           emu.current.uc_mcontext.arm_pc);

    setcontext((const ucontext_t *)&emu.current); /* never returns */
}

int emu_stop_trigger(const char *assembly) {
    static const char special[] = {"bkpt 0x0002"};
    /* static const char special[] = {"mov pc, lr"}; */

    if (strncmp(assembly, special, strlen(special)) == 0) {
        printf("\n");
        emu_printf("special op %s being skipped\n", special);
        CPU(pc) += 4;
        return 1;
    }
    return 0;
}

/* Setup emulation handler. */
void emu_register_handler(void* sig_handler) {
#if HAVE_SETRLIMIT
    /* Be recursion friendly */
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 0x100000; /* 1 MB */
    setrlimit (RLIMIT_STACK, &rl);
#endif

    /* 1. setup alternate stack for handler */
    stack_t ss;
    static char stack[SIGSTKSZ];

    /* ss.ss_sp = malloc(SIGSTKSZ); */
    ss.ss_sp = stack;
    if (ss.ss_sp == NULL) {
        perror("ss.ss_sp == NULL");
        exit(1);
    }
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
        perror("sigaltstack"); 
        exit(1);
    }

    /* 2. setup signal handler */
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sig_handler;
    /* sigaction (SIGSEGV, &sa, NULL); */
    sigaction (SIGPROF, &sa, NULL);
    sigaction (SIGTRAP, &sa, NULL);
}

const char* emu_disas(unsigned int pc) {
    /* printf("emu: %0lx: %0x\n", cpu(pc), *(unsigned int *)cpu(pc)); // if all else fails */
    static RAsmOp rop;

    static const int len = 4;         /* diassemble 4 bytes (A32) */
    r_asm_set_pc(rasm, pc);
    r_asm_disassemble(rasm, &rop, (const unsigned char *)pc, len);
    printf("disas: %x %08x %s\n", pc, *(const unsigned int *)pc, rop.buf_asm);

    return rop.buf_asm;
}

const darm_t* emu_darm(unsigned int pc) {
    const unsigned int ins = *(const unsigned int *)pc;

    if (armv7_disassemble(darm, ins)) {
        printf("darm : %x %08x <invalid instruction>\n", pc, ins);
    } else {
        /* printf("d : %x %08x %s\n", pc, ins, darm_str(d, pc)); */
        /* printf("darm : %x %08x %s\n", pc, ins, "[darm_str not implemented]"); */
    }

    return darm;
}

/* map register number (0-15) to ucontext reg entry (r0-r10, fp, ip, sp, lr pc) */
static inline uint32_t emu_read_reg(darm_reg_t reg) {
    assert(reg >= 0 && reg <= 15);
    switch(reg) {
    case r0  :
    case r1  :
    case r2  :
    case r3  :
    case r4  :
    case r5  :
    case r6  :
    case r7  :
    case r8  :
    case r9  :
    case r10 :
    case FP  :
    case IP  :
    case SP  :
    case LR  : return emu_regs[reg];
    case PC  : return emu_regs[reg] + 8; /* A32 +8, Thumb +4 */
    default  : return -1;
    }
    return -1;
}

static inline uint32_t *emu_write_reg(darm_reg_t reg) {
    assert(reg >= 0 && reg <= 15);
    return &emu_regs[reg];
}

/* Debugging */

static void dbg_dump_ucontext(ucontext_t *uc) {
    static int i;
    for (i = 0; i < SIGCONTEXT_REG_COUNT; i++) {
        printf("dbg: %14s: 0x%0x\n",
               sigcontext_names[i],
               ((uint32_t *)&uc->uc_mcontext)[i]);
    }
}

static void emu_dump() {
    dbg_dump_ucontext(&emu.current);
}

/* show register changes since last diff call */
static void emu_dump_diff() {
    static int i;
    for (i = 0; i < SIGCONTEXT_REG_COUNT; i++) {
        uint32_t current  = ((uint32_t *)&emu.current.uc_mcontext)[i];
        uint32_t previous = ((uint32_t *)&emu.previous.uc_mcontext)[i];
        if (current != previous) {
            printf("dbg: %-4s: %8x -> %8x\n",
                   sigcontext_names[i],
                   previous, current);
        }
    }
    emu.previous = emu.current;
}
