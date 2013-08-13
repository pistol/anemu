#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>           /* mprotect */
#include <errno.h>

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

#include "anemu-private.h"

#define TAINT_CLEAR 0x0

uint8_t emu_regs_tainted() {
    int i, tainted;
    tainted = N_REGS;
    for (i = 0; i < N_REGS; i++) {
        if (emu.taintreg[i] != TAINT_CLEAR) {
            emu_printf("r%d tainted tag: %x\n", i, emu.taintreg[i]);
        } else {
            tainted--;
        }
    }
    return tainted;
}

/* SIGTRAP handler used for single-stepping */
static void emu_handler(int sig, siginfo_t *si, void *ucontext) {
    uint32_t pc = (*(ucontext_t *)ucontext).uc_mcontext.arm_pc;

    emu_printf("SIG %d with TRAP code: %d pc: %x addr: %x\n",
               sig,
               si->si_code,
               pc,
               (int) si->si_addr);

    emu_init((ucontext_t *)ucontext); /* one time emu state initialization */
    emu_start();
    emu_stop();
}

void emu_init(ucontext_t *ucontext) {
    assert(*emu.enabled == false);

    emu_printf("saving original ucontext ...\n");
    emu.previous = emu.current = emu.original = *ucontext;
    emu.regs = (uint32_t *)&emu.current.uc_mcontext.arm_r0;
    emu.branched = 0;

    emu_dump();

    if (emu.initialized == 1) return;
    emu_printf("initializing rasm2 disassembler ...\n");

    /* init darm */
    emu_printf("initializing darm disassembler ...\n");
    darm = malloc(sizeof(darm_t));

    /* process maps */
    emu_map_parse();

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
    case C_LS: return (( cpsr.C == 0) || (cpsr.Z == 1));
    case C_GE: return (  cpsr.N == cpsr.V);
    case C_LT: return (  cpsr.N != cpsr.V);
    case C_GT: return (( cpsr.Z == 0) && (cpsr.N == cpsr.V));
    case C_LE: return (( cpsr.Z == 1) || (cpsr.N != cpsr.V));
    case C_AL: return 1;
    case C_UNCOND: return 1;
    default: {
        emu_printf("unknown condition %x\n", cond);
        return 0;
    }
    }
}

void emu_type_arith_shift(const darm_t * d) {
    assert(d->Rs || d->shift);
    uint32_t sreg = emu_regshift(d);
    emu_printf("sreg = %x\n", sreg);
    EMU(WREG(Rd) = OP(RREG(Rn), sreg));
    TREG(Rd, Rn, Rm);
}

void emu_type_arith_imm(const darm_t * d) {
    if (d->S) {
        printf("S flag, we're Screwed!\n");

        switch((uint32_t) d->instr) {
            CASE(ADD, RdRnImm);
            CASE(ADC, RdRnImm);
            CASE(AND, RdRnImm);
            CASE(ASR, RdRnImm);
            CASE(BIC, RdRnImm);
            CASE(EOR, RdRnImm);
            CASE(LSL, RdRnImm);
            CASE(LSR, RdRnImm);
            CASE(ORR, RdRnImm);
            CASE(ROR, RdRnImm);
            CASE(RSB, RdRnImm);
            CASE(RSC, RdRnImm);
            CASE(SBC, RdRnImm);
            CASE(SUB, RdRnImm);

            SWITCH_COMMON;
        }
    } else {
        switch((uint32_t) d->instr) {
        case I_ADD:
        case I_ADC:
        case I_AND:
        case I_ASR:
        case I_BIC:
        case I_EOR:
        case I_LSL:
        case I_LSR:
        case I_ORR:
        case I_ROR:
        case I_RSB:
        case I_RSC:
        case I_SBC:
        case I_SUB: {
            EMU(WREG(Rd) = OP(RREG(Rn), d->imm));
            break;
        }
        case I_ADR: {
            uint32_t addr = d->U ?
                (RREGN(PC) + d->imm) :
                (RREGN(PC) - d->imm);
            EMU(WREG(Rd) = addr);
            break;
        }
            SWITCH_COMMON;
        }
    }
}

void SelectInstrSet(cpumode_t mode) {
    switch(mode) {
    case M_ARM: {
        if (CurrentInstrSet() == M_THUMB) {
            printf("Thumb -> ARM switch!\n");
        }
        CPU(cpsr) &= ~PSR_T_BIT;
        break;
    }
    case M_THUMB: {
        if (CurrentInstrSet() == M_ARM) {
            printf("ARM -> Thumb switch!\n");
        }
        CPU(cpsr) |=  PSR_T_BIT;
        break;
    }
    default:
        emu_abort("invalid instruction set %d\n", mode);
    }
}

cpumode_t CurrentInstrSet() {
    return (emu_thumb_mode() ? M_THUMB : M_ARM);
}

cpumode_t TargetInstrSet(uint32_t instr) {
    if (instr == I_BX) {        /* swap mode */
        return (CurrentInstrSet() == M_ARM ? M_THUMB : M_ARM);
    } else {                    /* keep current mode */
        return (CurrentInstrSet());
    }
}

void BranchWritePC(uint32_t addr) {
    EMU_ENTRY;

    emu_printf("RREGN(PC): %x\n", RREGN(PC));
    emu_printf("addr: %x\n", addr);
    if (CurrentInstrSet() == M_ARM) {
        EMU(WREGN(PC) = addr & ~0b11);
    } else {
        EMU(WREGN(PC) = addr & ~0b1);
    }
}

void BXWritePC(uint32_t addr) {
    EMU_ENTRY;

    emu_printf("RREGN(PC): %x\n", RREGN(PC));
    if (addr & 1) {
        SelectInstrSet(M_THUMB);
        EMU(WREGN(PC) = addr & ~1);
    } else if (addr & ~0b10) {
        SelectInstrSet(M_ARM);
        EMU(WREGN(PC) = addr);
    } else {
        emu_abort("invalid branch addr: %x", addr);
    }
}

void emu_type_branch_syscall(const darm_t * d) {
    switch((uint32_t) d->instr) {
    case I_B: {
        BranchWritePC(RREGN(PC) + d->imm);
        break;
    }
    case I_BL:
    case I_BLX: {               /* immediate */
        if (CurrentInstrSet() == M_ARM) {
            EMU(WREGN(LR) =   RREGN(PC) - 4);
        } else {
            EMU(WREGN(LR) = ((RREGN(PC) - 2) | 1));
        }
        uint32_t targetAddress;
        cpumode_t targetInstrSet = TargetInstrSet(d->instr);
        if (targetInstrSet == M_ARM) {
            targetAddress = Align(RREGN(PC), 4) + d->imm;
        } else {
            targetAddress = RREGN(PC) + d->imm;
        }
        SelectInstrSet(targetInstrSet);
        BranchWritePC(targetAddress);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_branch_misc(const darm_t * d) {
    switch((uint32_t) d->instr) {
    case I_BKPT: {
        /* special flags */
        /* entering- JNI: 1337 */
        /* emu_single_step(); */
        if (d->imm == MARKER_START_VAL) {
            emu_printf("MARKER: starting emu\n");
        } else if (d->imm == MARKER_STOP_VAL) {
            emu_printf("MARKER: leaving emu due to JNI re-entry\n");
            emu_advance_pc();
            emu_stop();
        } else {
            emu_abort("MARKER: unexpected value! %x\n", d->imm);
        }
        break;
    }
    case I_BX: {
        BXWritePC(RREG(Rm));
        break;
    }
    case I_BLX: {
        if (CurrentInstrSet() == M_ARM) {
            EMU(WREGN(LR) =   RREGN(PC) - 4);
        } else {
            EMU(WREGN(LR) = ((RREGN(PC) - 2) | 1));
        }
        BXWritePC(RREG(Rm));
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_move_imm(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_MOV: {
        if (d->S) {
            EMU_FLAGS_RdImm(MOV);
        } else {
            EMU(WREG(Rd) = d->imm);
        }
        break;
    }
    case I_MOVT: {
        EMU(WREG(Rd) = (RREG(Rd) & 0x0000ffff) | (d->imm << 16));
        break;
    }
    case I_MOVW: {
        EMU(WREG(Rd) = (RREG(Rd) & 0xffff0000) | (d->imm));
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
                      : [ps] "=r" (CPU(cpsr))                      /* output */
                      : [a] "r" (RREG(Rn)), [b] "r" (RREG(Rm))     /* input */
                      : "cc"                                       /* clobbers condition codes */
                      );
        CPSR_UPDATE_BITS;
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_cmp_imm(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_CMP: {
        asm volatile (
                      "cmp %[a], %[b]\n\t"                         /* updates flags */
                      "mrs %[ps], CPSR\n\t"                        /* save new cpsr */
                      : [ps] "=r" (CPU(cpsr))                      /* output */
                      : [a] "r" (RREG(Rn)), [b] "r" (d->imm)       /* input */
                      : "cc"                                       /* clobbers condition codes */
                      );
        CPSR_UPDATE_BITS;
        break;
    }
        SWITCH_COMMON;
    }
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
        EMU(WREG(Rd) = RREG(Rm));
    case I_LSL: {
        EMU(WREG(Rd) = LSL(RREG(Rm), d->shift));
        WTREG1(Rd, Rm);
        break;
    }
    case I_LSR: {
        EMU(WREG(Rd) = LSR(RREG(Rm), d->shift));
        WTREG1(Rd, Rm);
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
    case I_LDR:
    case I_LDRB: {
        uint32_t imm = (d->Rm == R_INVLD) ? d->imm : RREG(Rm);
        uint32_t offset_addr = d->U ?
            (RREG(Rn) + imm) :
            (RREG(Rn) - imm);

        uint32_t addr = d->P ?
            offset_addr :
            RREG(Rn);

        if ((d->W == 1) || (d->P == 0)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

        map_t *m = emu_map_lookup(addr);
        if (m) printf("addr: %x %s\n", addr, m->name);
        printf("RMEM: %x\n", RMEM(addr));

        if (d->instr == I_LDR) {
            EMU(WREG(Rt) = RMEM(addr));
        } else {
            EMU(WREG(Rt) = RMEM(addr) & 0xFFFF);
        }
        if ((d->Rt == PC) && (RREG(Rt) & 1)) {
            printf("ARM -> Thumb switch!\n");
            CPU(cpsr) |=  PSR_T_BIT;
        } else {
            CPU(cpsr) &= ~PSR_T_BIT;
        }
        break;
    }
    case I_STR:
    case I_STRB: {
        uint32_t offset_addr = d->U ?
            (RREG(Rn) + d->imm) :
            (RREG(Rn) - d->imm);

        uint32_t addr = d->P ?
            offset_addr :
            RREG(Rn);

        if ((d->W == 1) || (d->P == 0)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

        map_t *m = emu_map_lookup(addr);
        if (m) printf("addr: %x %s\n", addr, m->name);

        /* EMU(WMEM(addr) = RREG(Rt)); */
        if (d->instr == I_STR) {
            WMEM(addr) = RREG(Rt);
        } else {
            WMEM(addr) = RREG(Rt) & 0xFFFF;
        }
        break;
    }
    case I_PUSH: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = BitCount(reglist); /* number of bits set to 1 */
        uint32_t addr          = RREG(Rn) - 4 * regcount;
        uint8_t reg            = 0;

        while (reglist) {
            reg            = TrailingZerosCount(reglist); /* count trailing zeros */
            reglist       &= ~(1 << reg);                 /* unset this bit */
            printf("addr: %x, r%d: %8x\n", addr, reg, RREGN(reg));
            WMEM(addr)     = RREGN(reg);
            /* EMU(WMEM(addr) = RREGN(reg)); */
            addr          += 4;
        }

        /* EMU(WREG(Rn) = RREG(Rn) - 4 * regcount); /\* update SP *\/ */
        WREG(Rn) = RREG(Rn) - 4 * regcount; /* update SP */
        break;
    }
    case I_POP: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = BitCount(reglist); /* number of bits set to 1 */
        uint32_t addr          = RREG(Rn);
        uint8_t reg            = 0;

        while (reglist) {
            reg            = TrailingZerosCount(reglist); /* count trailing zeros */
            reglist       &= ~(1 << reg);                 /* unset this bit */
            printf("addr: %x, r%d: %8x\n", addr, reg, RMEM(addr));
            /* EMU(WREGN(reg) = RMEM(addr)); */
            WREGN(reg) = RMEM(addr);
            addr          += 4;
        }

        EMU(WREG(Rn) = RREG(Rn) + 4 * regcount); /* update SP */
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_uncond(const darm_t * d) {
    EMU_ENTRY;

    switch((uint32_t) d->instr) {
    case I_DMB: {
        /* Options: SY, ST, ISH, ISHST, NSH, NSHST, OSH, OSHST */
        switch(d->option) {
        case O_SY: {
            DMB(SY);
            break;
        }
        case O_ST: {
            DMB(ST);
            break;
        }
        default: {
            emu_abort("unsupported barrier option %d\n", d->option);
        }
        }
        break;
    }
    case I_PLD: {
        emu_printf("treating PLD as NOP\n");
        break;
    }
        SWITCH_COMMON;
    }
}

inline uint32_t emu_dataop(const darm_t *d, const uint32_t a, const uint32_t b) {
    switch((uint32_t) d->instr) {
    case I_CMN :
    case I_ADD : return  a + b;
    case I_ADC : return  a + b  +  cpsr.C;
    case I_CMP :
    case I_SUB : return  a - b;
    case I_SBC : return (a - b) - !cpsr.C;
    case I_RSC : return (b - a) - !cpsr.C;
    case I_RSB : return  b - a;
    case I_TEQ :
    case I_EOR : return  a ^ b;
    case I_TST:
    case I_AND : return  a & b;
    case I_ORR : return  a | b;
    case I_BIC : return  a & ~b;
    case I_MOV : return   b;
    case I_MVN : return  ~b;
    default: emu_abort("unhandled dataop %s\n", darm_mnemonic_name(d->instr));
    }
    return 0xdeadc0de;
}

inline uint32_t emu_regshift(const darm_t *d) {
    uint32_t amount = d->Rs != R_INVLD ? RREG(Rs) : d->shift; /* shift register value or shift constant */
    uint32_t val = RREG(Rm);

    if (amount == 0) return val;

    switch(d->shift_type) {
    case S_LSL: return LSL(val, amount);
    case S_LSR: return LSR(val, amount);
    case S_ASR: return ASR(val, amount);
    case S_ROR: return ROR(val, amount);
    default: emu_abort("invalid shift type %s!\n", darm_shift_type_name(d->shift_type));
    }
    return val;
}

static void emu_advance_pc() {
    if (!emu.branched) CPU(pc) += (emu_thumb_mode() ? 2 : 4);
    emu.branched = 0;
    emu_dump_diff();
    emu_regs_tainted();
    printf("\n");
    printf("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
}

#define TAINT_MAP_SIZE 4096

/* function of type HashCompareFunc */
static int hashcmpTaintInfo(const void* ptr1, const void* ptr2)
{
    assert(ptr1 != NULL && ptr2 != NULL);

    taintinfo_t* t1 = (taintinfo_t*) ptr1;
    taintinfo_t* t2 = (taintinfo_t*) ptr2;

    /* 0 - equal, 1 - different, based on strcmp*/
    return (t1->addr == t2->addr) ? 0 : 1;
}

static int emu_dump_taintinfo(void* entry, UNUSED void* arg) {
    taintinfo_t* ti = (taintinfo_t *) entry;
    if (ti->tag != TAINT_CLEAR) {
        printf("taint: addr: %x tag: %x", ti->addr, ti->tag);
    }
    return 0;
}

void emu_set_taint_mem(uint32_t addr, uint32_t tag) {
    if (emu.taintmap == NULL) {
        printf("initializing taintmap ...\n");
        emu.taintmap = dvmHashTableCreate(dvmHashSize(TAINT_MAP_SIZE), NULL);
        printf("taintmap addr:\n");
        emu_map_lookup((uint32_t)emu.taintmap);
    }

    emu_printf("addr: %x\n", addr);
    emu_map_lookup(addr);

    /* FIXME: avoid malloc! */
    taintinfo_t *ti = malloc(sizeof(taintinfo_t));
    ti->addr = addr;
    ti->tag  = tag;

    int hash = ti->addr;
    taintinfo_t* added = (taintinfo_t *)dvmHashTableLookup(emu.taintmap, hash, (void *) ti,
                                                           hashcmpTaintInfo, true);
    if (added == NULL) {
        printf("taint not set!");
    } else {                    /* addr already exists in hash, update tag */
        if (added->tag != TAINT_CLEAR && ti->tag == TAINT_CLEAR) {
            printf("taint: un-tainting mem: %x\n", addr);
        } else if (added->tag == TAINT_CLEAR && ti->tag != TAINT_CLEAR) {
            printf("taint: tainting mem: %x tag: %x\n", ti->addr, ti->tag);
        }
        added->tag = ti->tag;
    }

    // dump hashtable
    printf("dumping taint hashtable...\n");
    dvmHashForeach(emu.taintmap, emu_dump_taintinfo, NULL);
}

static int emu_protect_page(void* addr, void* flags) {
    mprotectPage((uint32_t)addr, (uint32_t)flags);
    return 0;
}

static int emu_unique_pages(void* entry, UNUSED void* arg) {
    taintinfo_t* ti = (taintinfo_t *) entry;

    /* one-time initialization of unique pages hash */
    if (emu.uniquepages == NULL) {
        printf("initializing unique taint pages hash ...\n");
        emu.uniquepages = dvmHashTableCreate(dvmHashSize(TAINT_MAP_SIZE), NULL);
    }

    /* clear unique hash */
    dvmHashTableClear(emu.uniquepages);

    if (ti->tag != TAINT_CLEAR) {
        uint32_t addr_aligned = getAlignedPage(ti->addr);
        int hash = addr_aligned;
        dvmHashTableLookup(emu.uniquepages, hash, (void *) addr_aligned,
                           hashcmpTaintInfo, true);
    }
    return 0;
}

static void emu_protect_mem() {
    /* build unique list of pages to protect to avoid infinite trap recursion */
    dvmHashForeach(emu.taintmap, emu_unique_pages, NULL);

    /* protect all pages in unique hash */
    uint32_t flags = PROT_NONE;
    dvmHashForeach(emu.uniquepages, emu_protect_page, (void *)flags);
}

static void emu_unprotect_mem() {
    assert(emu.uniquepass != NULL);

    /* un-protect all pages in unique hash */
    uint32_t flags = PROT_READ | PROT_WRITE;
    dvmHashForeach(emu.uniquepages, emu_protect_page, (void *)flags);
}

static uint32_t emu_get_taint_mem(uint32_t addr) {
    taintinfo_t tinfo;
    tinfo.addr = addr;
    taintinfo_t* ti = &tinfo;

    assert(emu.taintmap != NULL);

    int hash = ti->addr;
    taintinfo_t* found = (taintinfo_t *)dvmHashTableLookup(emu.taintmap, hash, (void *) ti,
                                                           hashcmpTaintInfo, false);
    if (found == NULL) {
        /* printf("address not tainted!"); */
        return TAINT_CLEAR;
    } else {
        printf("taint: addr: %x tag: %x", ti->addr, found->tag);
        return found->tag;
    }
}

static inline void emu_set_taint_reg(uint32_t reg, uint32_t tag) {
    if (emu.taintreg[reg] != TAINT_CLEAR && tag == TAINT_CLEAR) {
        printf("taint: un-tainting r%d\n", reg);
    } else if (emu.taintreg[reg] == TAINT_CLEAR && tag != TAINT_CLEAR) {
        printf("taint: tainting r%d tag: %x", reg, tag);
    }
    emu.taintreg[reg] = tag;
}

static inline uint32_t emu_get_taint_reg(uint32_t reg) {
    return emu.taintreg[reg];
}

void emu_singlestep(uint32_t pc) {
    // 1. decode instr
    emu_map_lookup(pc);

    printf("emu_disasm_ref ...\n");
    // emu_disasm_ref(pc, (emu_thumb_mode() ? 16 : 32)); /* rasm2 with libopcodes backend */
    /* static const darm_t *d; */
    const darm_t *d;
    printf("emu_disasm ...\n");
    d = emu_disasm(pc); /* darm */
    /* check for invalid disassembly */
    /* best we can do is stop emu and resume execution at the instruction before the issue */
    if (!d) {
        // FIXME: hacky detect mcr
        // ee1d0f70 mrc 15, 0, r0, cr13, cr0, {3}
        if (*(const uint32_t*)pc == 0xee1d0f70) {
            asm volatile("mrc 15, 0, %[reg], cr13, cr0, 3" : [reg] "=r" CPU(r0));
            goto next;
        } else {
            emu_abort("invalid disassembly"); /* emu_stop() will get called after */
        }
    }
    darm_dump(d);           /* dump internal darm_t state */

    if (!emu_eval_cond(d->cond)) {
        emu_printf("skipping instruction: condition NOT passed\n");
        goto next;
    }

    // 2. emu instr by type
    switch(d->instr_type) {
    case T_ARM_ARITH_SHIFT: {
        emu_type_arith_shift(d);
        break;
    }
    case T_ARM_ARITH_IMM: {
        emu_type_arith_imm(d);
        break;
    }
    case T_ARM_BRNCHSC: {
        emu_type_branch_syscall(d);
        break;
    }
    case T_ARM_BRNCHMISC: {
        emu_type_branch_misc(d);
        break;
    }
    case T_ARM_MOV_IMM: {
        emu_type_move_imm(d);
        break;
    }
    case T_ARM_CMP_IMM: {
        emu_type_cmp_imm(d);
        break;
    }
    case T_ARM_CMP_OP: {
        emu_type_cmp_op(d);
        break;
    }
    case T_ARM_OPLESS: {
        emu_type_opless(d);
        break;
    }
    case T_ARM_DST_SRC: {
        emu_type_dst_src(d);
        break;
    }
    case T_ARM_STACK0:
    case T_ARM_STACK1:
    case T_ARM_STACK2:
    case T_ARM_LDSTREGS: {
        emu_type_memory(d);
        break;
    }
    case T_ARM_UNCOND: {
        emu_type_uncond(d);
        break;
    }
    case T_ARM_PUSR: {
        emu_type_pusr(d);
        break;
    }
    case T_ARM_SYNC: {
        emu_type_sync(d);
        break;
    }
    case T_INVLD: {
        emu_abort("darm invalid type (unsupported yet)\n");
        break;
    }
    default:
        emu_abort("unhandled type %s\n", darm_enctype_name(d->instr_type));
    }

 next:
    emu_advance_pc();
}

void emu_start() {
    emu_printf("starting emulation ...\n\n");

    // determine entry mode: emu or trap-single-step-emu
    // read arguments from JNI trap: addr + tag
    if (!emu.tinfo->addr || !emu.tinfo->tag ) {
        emu_abort("taint: trap taint info invalid");
    }

    emu_set_taint_mem(emu.tinfo->addr, emu.tinfo->tag);
    *emu.enabled = 1;

    while(1) {                  /* infinite loop */
        emu_singlestep(CPU(pc));
    }
}

/* note: ucontext/setcontext support normally missing in Bionic */
/* unless ported to Bionic, hack it by returning 0 */
/* int setcontext (const ucontext_t *ucp) { return 0; } */

void emu_stop() {
    emu_printf("resuming exec pc old: 0x%0lx new: 0x%0lx\n",
               emu.original.uc_mcontext.arm_pc,
               emu.current.uc_mcontext.arm_pc);

    *emu.enabled = 0;
    if (emu_regs_tainted()) {
        emu_printf("WARNING: stopping emu with tainted regs!\n");
    }
    setcontext((const ucontext_t *)&emu.current); /* never returns */
}

uint8_t emu_stop_trigger() {
    static const darm_instr_t trigger = I_BKPT;

    if (darm->instr == trigger) {
        printf("\n");
        emu_printf("special op %s being skipped\n", darm_mnemonic_name(trigger));
        CPU(pc) += 4;
        return 1;
    }
    return 0;
}

/* Setup emulation handler. */
void emu_register_handler(DvmEmuGlobals* state) {
    if (state == NULL) {
        printf("shared state == NULL");
        exit(1);
    }
    emu.tinfo   = &state->tinfo;
    emu.enabled = &state->enabled;

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
    sa.sa_sigaction = emu_handler;
    /* sigaction (SIGSEGV, &sa, NULL); */
    sigaction (SIGPROF, &sa, NULL);
    sigaction (SIGTRAP, &sa, NULL);

    /* 3. setup mprotect handler */
    mprotectInit();
}

const darm_t* emu_disasm(uint32_t pc) {
    return emu_disasm_internal(darm, pc); /* darm is a global variable */
}

const darm_t* emu_disasm_internal(darm_t *d, uint32_t pc) {
    uint32_t ins = *(const uint32_t *)pc;

    // Thumb16 only for now
    /* if (emu_thumb_mode()) ins &= 0xffff; */

    darm_str_t str;
    if (emu_thumb_mode()) {
        /* T16 mode */
        if (darm_thumb_disasm(d, ins)) {
            emu_printf("darm : %x %04x <invalid instruction>\n", pc, (uint16_t)ins);
            return NULL;
        } else {
            darm_str2(d, &str, 1); /* lowercase str */
            printf("darm : %x %04x %s\n", pc, (uint16_t)ins, str.total);
        }
    } else {
        /* A32 mode */
        if (darm_armv7_disasm(d, ins)) {
            emu_printf("darm : %x %08x <invalid instruction>\n", pc, ins);
            return NULL;
        } else {
            darm_str2(d, &str, 1); /* lowercase str */
            printf("darm : %x %08x %s\n", pc, ins, str.total);
        }
    }
    return d;
}

static inline uint8_t emu_thumb_mode() {
    return (CPU(cpsr) & PSR_T_BIT);
}

/* map register number (0-15) to ucontext reg entry (r0-r10, fp, ip, sp, lr pc) */
static inline uint32_t emu_read_reg(darm_reg_t reg) {
    assert(reg >= 0 && reg <= 15);
    if (reg == R_INVLD) return R_INVLD;

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
    case LR  : return emu.regs[reg];
    case PC  : return emu.regs[reg] + (emu_thumb_mode() ? 4 : 8); /* A32 +8, Thumb +4 */
    default  : return -1;
    }
    return -1;
}

static inline uint32_t *emu_write_reg(darm_reg_t reg) {
    assert(reg >= 0 && reg <= 15);
    if (reg == R_INVLD) return NULL;

    /* if we are explicitly writing the PC, we are branching */
    /* we clear flag in main loop when ready to fetch next op */
    if (reg == PC) emu.branched = 1;
    return &emu.regs[reg];
}

/* Debugging */

static void dbg_dump_ucontext(ucontext_t *uc) {
    static int i;
    for (i = 0; i < SIGCONTEXT_REG_COUNT; i++) {
        printf("dbg: %14s: %0x\n",
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

static void emu_map_dump(map_t *m) {
    if (m != NULL) {
        printf("%x-%x %c%c%c%c %x %x:%x %u %s [%u pages]\n",
               m->vm_start,
               m->vm_end,
               m->r, m->w, m->x, m->s,
               m->pgoff,
               m->major, m->minor,
               m->ino,
               m->name,
               m->pages);
    } else {
        emu_abort("invalid (null) map\n");
    }
}

// Sample format
// 00400000-004d0000 r-xp 00000000 08:01 3973335 /usr/bin/irssi
static void emu_map_parse() {
    FILE *file;
    char buf[1024];
    emu.nr_maps = 0;

    file = fopen("/proc/self/maps", "r");
    if (!file) {
        perror(buf);
        exit(EXIT_FAILURE);
    }

    int32_t page_size = getPageSize();

    while (fgets(buf, sizeof(buf), file) != NULL) {
        map_t m;
        unsigned int n;

        memset(&m, 0, sizeof(map_t));

        n = sscanf(buf, "%x-%x %c%c%c%c %x %x:%x %u %255s",
                   &m.vm_start,
                   &m.vm_end,
                   &m.r, &m.w, &m.x, &m.s,
                   &m.pgoff,
                   &m.major, &m.minor,
                   &m.ino,
                   m.name);
        m.pages = (m.vm_end - m.vm_start) / page_size;
        emu_map_dump(&m);
        if (n < 10) {
            printf("unexpected line: %s\n", buf);
            continue;
        }
        emu.maps[emu.nr_maps] = m;
        if (++emu.nr_maps >= MAX_MAPS) {
            printf("too many maps\n");
            break;
        }
    }
    fclose(file);
}

static map_t* emu_map_lookup(uint32_t addr) {
    unsigned int i;
    map_t *m;

    for (i = 0; i < emu.nr_maps; i++) {
        m = &emu.maps[i];
        if (addr >= m->vm_start && addr <= m->vm_end) {
            printf("lib map %8x -> %8x\n", addr, addr - m->vm_start);
            emu_map_dump(m);
            return m;
        }
    }
    printf("unable to locate addr: %x\n", addr);
    return NULL;
}

/* Page Protection */

static inline int32_t
getPageSize() {
    static int32_t pageSize = 0;

    /* previous invocations will set pageSize */
    if (pageSize) return pageSize;

    /* this code executes once at initialization */
    pageSize = sysconf(_SC_PAGE_SIZE);
    if (pageSize == -1)
        emu_printf("error: sysconf %d", pageSize);

    printf("Page Size = %d bytes\n", pageSize);

    return pageSize;
}

static inline uint32_t
getAlignedPage(uint32_t addr) {
    return addr & ~ (getPageSize() - 1);
}

static void
mprotectHandler(int sig, siginfo_t *si, void *ucontext) {
    uint32_t pc = (*(ucontext_t *)ucontext).uc_mcontext.arm_pc;
    uint32_t addr_fault = (*(ucontext_t *)ucontext).uc_mcontext.fault_address;

    printf("\n### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ###\n");

    emu_printf("SIG %d with TRAP code: %d pc: %x addr: %x\n",
               sig,
               si->si_code,
               pc,
               addr_fault);

    assert(si_addr == addr_fault);

    emu_map_lookup(pc);
    emu_map_lookup(addr_fault);

    if (*emu.enabled == 1) {
        dbg_dump_ucontext((ucontext_t *)ucontext);
        emu_abort("massive fuckup, trapping while in emu!\n");
    }

    emu_init((ucontext_t *) ucontext);

    uint32_t addr_aligned = getAlignedPage(addr_fault);
    printf("fault addr: %x fixing permissions for page: %x\n", addr_fault, addr_aligned);

    mprotectPage(addr_fault, PROT_READ | PROT_WRITE); /* will align internally */

    if (emu_get_taint_mem(addr_fault) != TAINT_CLEAR) {
        /* disable mprotect on all tainted pages to avoid re-traping while in emu */
        emu_unprotect_mem();
        emu_start();            /* never returns */
    } else {
        /* false positive, single-step instruction and re-enable protection */
        /* NOTE: we don't expect single-step to access a tainted mem location */
        /* Hence we skip unprotect+protect tainted memory */
        /* emu_unprotect_mem(); */

        printf("un-protecting mem before singlestep...\n");
        emu_unprotect_mem();

        *emu.enabled = 1;

        printf("singlestep instruction at pc: %x\n", pc);
        emu_singlestep(pc);

        printf("protecting mem after singlestep...\n");
        emu_protect_mem();

        emu_stop();             /* this should not be reached */
    }
}

static void
mprotectInit() {
    struct sigaction sa;

    /* sa.sa_flags = SA_SIGINFO; */
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK; /* doesn't clobber original stack */
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = mprotectHandler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        emu_printf("error: sigaction");
}

/* TODO: add length and determine if page boundary crossed */
static void
mprotectPage(uint32_t addr, uint32_t flags) {
    uint32_t addr_aligned = getAlignedPage(addr); /* align at pageSize */
    printf("update protection on page: %x given addr: %x\n", addr_aligned, addr);
    emu_map_lookup(addr);

    if (mprotect((void *)addr_aligned, getPageSize(),
                 flags) == -1) {
        emu_printf("error: mprotect errno: %s\n", strerror(errno));
    }
    printf("page protection updated\n");
}
