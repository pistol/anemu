#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// #include <assert.h>
#include <signal.h>
#include <sys/mman.h>           /* mprotect */
#include <errno.h>
#include <asm/ptrace.h>         /* PSR bit macros */
#include <pthread.h>
#include <time.h>
#include <string.h>             /* memset */

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
        if (RTREGN(i) != TAINT_CLEAR) {
            if (i == SP ||
                i == LR ||
                i == PC) {
                emu_log_info("taint: WARNING special r%d tainted!\n", i);
            }
            emu_log_debug("taint: r%d val: %x tag: %x\n", i, RREGN(i), RTREGN(i));
        } else {
            tainted--;
        }
    }
    return tainted;
}

/* SIGTRAP handler used for single-stepping */
static void emu_handler(int sig, siginfo_t *si, void *ucontext) {
    pthread_mutex_lock(&emu.lock);
    uint32_t pc = (*(ucontext_t *)ucontext).uc_mcontext.arm_pc;

    emu_log_debug("SIG %d with TRAP code: %d pc: %x addr: %x\n",
               sig,
               si->si_code,
               pc,
               (int) si->si_addr);

    emu_init((ucontext_t *)ucontext); /* one time emu state initialization */
    emu_map_lookup(pc);
    emu_start();
    emu_stop();
}

void emu_init(ucontext_t *ucontext) {
    assert(emu.enabled == false);

    // emu_log_debug("saving original ucontext ...\n");
    emu.previous = emu.current = emu.original = *ucontext;
    emu.regs = (uint32_t *)&emu.current.uc_mcontext.arm_r0;
    emu.branched = 0;

    emu_dump();
}

uint8_t emu_eval_cond(uint32_t cond) {
    emu_dump_cpsr();

    switch(cond) {
    case C_EQ: return  CPSR_Z;
    case C_NE: return !CPSR_Z;
    case C_CS: return  CPSR_C;
    case C_CC: return !CPSR_C;
    case C_MI: return  CPSR_N;
    case C_PL: return !CPSR_N;
    case C_VS: return  CPSR_V;
    case C_VC: return !CPSR_V;
    case C_HI: return  CPSR_C && !CPSR_Z;
    case C_LS: return !CPSR_C ||  CPSR_Z;
    case C_GE: return  CPSR_N &&  CPSR_V;
    case C_LT: return  CPSR_N !=  CPSR_V;
    case C_GT: return !CPSR_Z && (CPSR_N == CPSR_V);
    case C_LE: return  CPSR_Z || (CPSR_N != CPSR_V);
    case C_AL: return 1;
    case C_UNCOND: return 1;
    default: {
        emu_abort("unknown condition %x\n", cond);
        return 0;
    }
    }
}

void emu_type_arith_shift(const darm_t * d) {
    emu_log_debug("Rs: %d shift_type: %d shift: %d\n", d->Rs, d->shift_type, d->shift);
    assert((d->Rs != R_INVLD) || (d->shift_type != S_INVLD) || (d->shift == 0));
    if (d->instr == I_BIC && d->shift == 0) {
        /* shift type 0 is LSL */
        EMU(WREG(Rd) = LSL(RREG(Rn), RREG(Rm)));
    } else {
        uint32_t sreg = emu_regshift(d);
        emu_log_debug("sreg = %x\n", sreg);
        /* FIXME: BIC has no Rs or shift */
        EMU(WREG(Rd) = OP(RREG(Rn), sreg));
    }
    WTREG2(Rd, Rn, Rm);
}

void emu_type_arith_imm(const darm_t * d) {
    if (d->S == B_SET) {
        emu_log_debug("S flag, we're Screwed!\n");

        switch(d->instr) {
            CASE_RRI(ADD, Rd, Rn, imm);
            CASE_RRI(ADC, Rd, Rn, imm);
            CASE_RRI(AND, Rd, Rn, imm);
            CASE_RRI(ASR, Rd, Rn, imm);
            CASE_RRI(BIC, Rd, Rn, imm);
            CASE_RRI(EOR, Rd, Rn, imm);
            CASE_RRI(LSL, Rd, Rn, imm);
            CASE_RRI(LSR, Rd, Rn, imm);
            CASE_RRI(ORR, Rd, Rn, imm);
            CASE_RRI(ROR, Rd, Rn, imm);
            CASE_RRI(RSB, Rd, Rn, imm);
            CASE_RRI(RSC, Rd, Rn, imm);
            CASE_RRI(SBC, Rd, Rn, imm);
            CASE_RRI(SUB, Rd, Rn, imm);

            SWITCH_COMMON;
        }
    } else {
        switch(d->instr) {
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
            WTREG1(Rd, Rn);
            break;
        }
        case I_ADR: {
            uint32_t addr = d->U == B_SET ?
                (RREGN(PC) + d->imm) :
                (RREGN(PC) - d->imm);
            if (d->Rd == PC) {
                BXWritePC(addr);
            } else {
                EMU(WREG(Rd) = addr);
                WTREG(Rd, RTMEM(addr));
            }
            break;
        }
            SWITCH_COMMON;
        }
    }
}

void emu_type_pusr(const darm_t * d) {
    switch(d->instr) {
    case I_UXTB: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = rotated & 0xffff;
        WTREG1(Rd, Rm);
        break;
    }
    SWITCH_COMMON;
    }
}

void emu_type_sync(const darm_t * d) {
    switch(d->instr) {
    case I_LDREX: {
        emu_log_debug("LDREX before:\n");
        emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM(RREG(Rn)));

        emu_log_debug("Checking for special lock aquire case...\n");
        darm_t d2, d3, d4;
        emu_disasm_internal(&d2, CPU(pc) +  4);
        emu_disasm_internal(&d3, CPU(pc) +  8);
        emu_disasm_internal(&d4, CPU(pc) + 12);

        /* __bionic_cmpxchg() */
        if (d2.instr == I_MOV &&
            d3.instr == I_TEQ &&
            d4.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STDEX)! Executing atomically.\n");

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "mov %[Rd2], #0\n"
                          "teq %[Rt], %[Rm3]\n"
                          "strexeq %[Rd2], %[Rt4], [%[Rn]]"
                          : [Rt] "=&r" (*emu_write_reg(d->Rt)), [Rd2] "=&r" (*emu_write_reg(d2.Rd))
                          : [Rn] "r" (emu_read_reg(d->Rn)), [Rm3] "Ir" (emu_read_reg(d3.Rm)), [Rt4] "r" (emu_read_reg(d4.Rt))
                          : "cc"
                          );

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTREGN(d2.Rd, TAINT_CLEAR);

            /* updating PC via WREGN is treated as a branch */
            /* which means PC is not advanced a further +2/4 */
            /* thus we have to use CPU(pc) instead of WREGN(pc) */
            CPU(pc) += 3 * 4;

            if (emu_read_reg(d2.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                /* FIXME: deadlock on malloc! */
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }
        }
        /* __bionic_atomic_dec() */
        else if (d2.instr == I_SUB &&
                 d3.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STDEX)! Executing atomically.\n");

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "sub %[Rd2], %[Rt], #1\n"
                          "strex %[Rd3], %[Rd2], [%[Rn]]"
                          : [Rt] "+r" (*emu_write_reg(d->Rt)), [Rd2] "+r" (*emu_write_reg(d2.Rd)), [Rd3] "=&r" (*emu_write_reg(d3.Rd))
                          : [Rn] "r" (emu_read_reg(d->Rn))
                          : "cc"
                          );

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTREGN(d2.Rd, RTREG(Rt));
            WTREGN(d3.Rd, TAINT_CLEAR);

            CPU(pc) += 3 * 4;

            if (emu_read_reg(d3.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                /* FIXME: deadlock on malloc! */
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }
        } else {
            asm volatile ("ldrex %[Rt], [%[Rn]]"
                          : [Rt] "=&r" (WREG(Rt))
                          : [Rn] "r" (RREG(Rn))
                          :
                          );

            WTREG1(Rt, Rn);
        }

        break;
    }
    case I_STREX: {
        emu_log_debug("STREX before:\n");
        emu_log_debug("Rt: %x\n", RREG(Rt));
        emu_log_debug("Rn: %x\n", RREG(Rn));
        emu_log_debug("Rd: %x\n", RREG(Rd));
        emu_log_debug("MEM Rn: %x\n", RMEM(RREG(Rn)));

        asm volatile ("strex %[Rd], %[Rt], [%[Rn]]"
                      : [Rd] "=&r" (WREG(Rd))
                      : [Rt] "r" (RREG(Rt)), [Rn] "r" (RREG(Rn))
                      : "memory"
                      );

        emu_log_debug("STREX after:\n");
        emu_log_debug("Rd: %x\n", RREG(Rd));
        emu_log_debug("MEM Rn: %x\n", RMEM(RREG(Rn)));

        if (RREG(Rd) == 0) {    /* 0 if memory was updated  */
            WTMEM(RREG(Rn), RTREG(Rt));
        } else {
            emu_abort("STREX failed to update memory\n");
        }
        break;
    }
    SWITCH_COMMON;
    }
}

void emu_type_mvcr(const darm_t * d) {
    switch(d->instr) {
    case I_MRC: {
        // FIXME: hacky detect mcr
        // ee1d0f70 mrc 15, 0, r0, cr13, cr0, {3}
        if (d->w == 0xee1d0f70) {
            asm volatile("mrc 15, 0, %[reg], cr13, cr0, 3" : [reg] "=r" CPU(r0));
        } else {
            emu_abort("unhandled encoding\n");
        }
        break;
    }
    SWITCH_COMMON;
    }
}

void SelectInstrSet(cpumode_t mode) {
    switch(mode) {
    case M_ARM: {
        if (CurrentInstrSet() == M_THUMB) {
            emu_log_debug("Thumb -> ARM switch!\n");
        }
        CPU(cpsr) &= ~PSR_T_BIT;
        break;
    }
    case M_THUMB: {
        if (CurrentInstrSet() == M_ARM) {
            emu_log_debug("ARM -> Thumb switch!\n");
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
    /* EMU_ENTRY; */

    emu_log_debug("RREGN(PC): %x\n", RREGN(PC));
    emu_log_debug("addr: %x\n", addr);
#ifndef PROFILE
    emu_map_lookup(addr);
#endif
    if (CurrentInstrSet() == M_ARM) {
        EMU(WREGN(PC) = addr & ~0b11);
    } else {
        EMU(WREGN(PC) = addr & ~0b1);
    }
}

void BXWritePC(uint32_t addr) {
    emu_log_debug("RREGN(PC): %x addr: %x\n", RREGN(PC), addr);
#ifndef PROFILE
    emu_map_lookup(addr);
#endif
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
    switch(d->instr) {
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
    case I_SVC: {
        /* "svc #0" is the only "svc" instruction in libc.so */
        if (d->imm == 0) {
            /* TODO: r7 expected (previous instruction writes it) */
            SVC(0);
        } else {
            emu_abort("unexpected SVC imm %x\n", d->imm);
        }
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_branch_misc(const darm_t * d) {
    switch(d->instr) {
    case I_BKPT: {
        /* special flags */
        /* entering- JNI: 1337 */
        /* emu_single_step(); */
        if (d->imm == MARKER_START_VAL) {
            emu_log_debug("MARKER: starting emu\n");
        } else if (d->imm == MARKER_STOP_VAL) {
            emu_log_debug("MARKER: leaving emu due to JNI re-entry\n");
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
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_MOV: {
        if (d->S == B_SET) {
            ASM_RI(MOV, Rd, imm);
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
    case I_MVN: {
        EMU(WREG(Rd) = ~d->imm);
        break;
    }
        SWITCH_COMMON;
    }
    WTREG(Rd, TAINT_CLEAR);
}

void emu_type_cmp_op(const darm_t * d) {
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_CMP: {
        ASM_RR_CMP(CMP, Rn, Rm);
        break;
    }
    case I_TEQ: {
        ASM_RR_CMP(TEQ, Rn, Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_cmp_imm(const darm_t * d) {
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_CMP: {
        ASM_RI_CMP(CMP, Rn, imm);
        break;
    }
    case I_TST: {
        ASM_RI_CMP(TST, Rn, imm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_opless(const darm_t * d) {
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_NOP: {
        /* nothing to do */
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_dst_src(const darm_t * d) {
    /* EMU_ENTRY; */

    if (d->S == B_SET) {
        emu_log_debug("S flag, we're Screwed!\n");

        switch(d->instr) {
            CASE_RR (MOV, Rd, Rm);
            CASE_RRI(LSL, Rd, Rm, shift);
            CASE_RRI(LSR, Rd, Rm, shift);
        case I_NOP: {
            /* nothing to do */
            break;
        }
            SWITCH_COMMON;
        }
    } else {
        switch(d->instr) {
        case I_MOV: {
            EMU(WREG(Rd) = RREG(Rm));
            break;
        }
        case I_LSL: {
            EMU(WREG(Rd) = LSL(RREG(Rm), d->shift));
            break;
        }
        case I_LSR: {
            EMU(WREG(Rd) = LSR(RREG(Rm), d->shift));
            break;
        }
        case I_NOP: {
            /* nothing to do */
            break;
        }
            SWITCH_COMMON;
        }
    }
    /* FIXME: what about NOP? */
    WTREG1(Rd, Rm);
}

void emu_type_memory(const darm_t * d) {
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_LDR:
    case I_LDRB: {
        uint32_t imm = (d->Rm == R_INVLD) ? d->imm : emu_regshift(d); /* RREG(Rm) or shift */
        uint32_t offset_addr = d->U == B_SET ?
            (RREG(Rn) + imm) :
            (RREG(Rn) - imm);

        uint32_t addr = d->P == B_SET ?
            offset_addr :
            RREG(Rn);

        if ((d->W == B_SET) || (d->P == B_UNSET)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

        emu_log_debug("Rt: %x\n", RREG(Rt));
        emu_log_debug("Rn: %x\n", RREG(Rn));
#ifndef PROFILE
        map_t *m = emu_map_lookup(addr);
        if (m) emu_log_debug("addr: %x %s\n", addr, m->name);
#endif
        if (d->instr == I_LDR &&
            addr != Align(addr, 4)) { /* unaligned addr */
            emu_abort("unaligned address");
        }

        uint32_t data;
        /* read 1, 2 or 4 bytes depending on instr type */
        data = RMEMB(addr);
        emu_log_debug("RMEMB: %x\n", data);
        if (d->Rt == PC) {
            if ((addr & b11) == 0) {
                BXWritePC(data);
            } else {
                emu_abort("unpredictable");
            }
        } else {                /* UnalignedSupport() || address<1:0> == '00' */
            EMU(WREG(Rt) = data);
            WTREG(Rt, RTMEM(addr));
        }

        break;
    }
    case I_STR:
    case I_STRB:
    case I_STRH: {
        uint32_t offset_addr = d->U == B_SET ?
            (RREG(Rn) + d->imm) :
            (RREG(Rn) - d->imm);

        uint32_t addr = d->P == B_SET ?
            offset_addr :
            RREG(Rn);

        if ((d->W == B_SET) || (d->P == B_UNSET)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

#ifndef PROFILE
        map_t *m = emu_map_lookup(addr);
        if (m) emu_log_debug("addr: %x %s\n", addr, m->name);
#endif
        if (addr != Align(addr, 4)) { /* word aligned */
            emu_abort("unaligned address");
        }
        /* depending on instr, 1, 2 or 4 bytes of RREG(Rt) will be used and stored to mem */
        WMEMB(addr, RREG(Rt));
        WTMEM(addr, RTREG(Rt));

        break;
    }
    case I_STM: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = BitCount(reglist); /* number of bits set to 1 */
        uint32_t addr          = RREG(Rn);
        uint8_t reg            = 0;

        while (reglist) {
            reg            = TrailingZerosCount(reglist); /* count trailing zeros */
            reglist       &= ~(1 << reg);                 /* unset this bit */
            emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RREGN(reg));
            WMEM(addr)     = RREGN(reg);
            if (RTMEM(addr) || RTREGN(reg)) WTMEM(addr, RTREGN(reg));
            WTMEM(addr, RTREGN(reg));
            addr          += 4;
        }
        if (d->W == B_SET) {    /* writeback */
            EMU(WREG(Rn) = RREG(Rn) + 4 * regcount);
        }
        break;
    }
    case I_LDM: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = BitCount(reglist); /* number of bits set to 1 */
        uint32_t addr          = RREG(Rn);
        uint8_t reg            = 0;

        while (reglist) {
            reg            = TrailingZerosCount(reglist); /* count trailing zeros */
            reglist       &= ~(1 << reg);                 /* unset this bit */
            emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RMEM(addr));
            if (reg == PC) break;
            /* EMU(WREGN(reg) = RMEM(addr)); */
            WREGN(reg) = RMEM(addr);
            if (RTREGN(reg) || RTMEM(addr)) WTREGN(reg, RTMEM(addr));
            addr          += 4;
        }
        if (BitCheck(d->reglist, PC)) {
            BXWritePC(RMEM(addr));
        }
        if (d->W == B_SET) {    /* writeback */
            if (BitCheck(d->reglist, d->Rn)) {
                EMU(WREG(Rn) = RREG(Rn) + 4 * regcount);
            } else {
                emu_abort("unknown Rn %d %x", d->Rn, RREG(Rn));
            }
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
            emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RREGN(reg));
            WMEM(addr)     = RREGN(reg);
            /* EMU(WMEM(addr) = RREGN(reg)); */
            if (RTMEM(addr) || RTREGN(reg)) WTMEM(addr, RTREGN(reg));
            addr          += 4;
        }

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
            emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RMEM(addr));
            if (reg == PC) break;
            /* EMU(WREGN(reg) = RMEM(addr)); */
            WREGN(reg) = RMEM(addr);
            if (RTREGN(reg) || RTMEM(addr)) WTREGN(reg, RTMEM(addr));
            addr          += 4;
        }
        if (BitCheck(d->reglist, PC)) {
            BXWritePC(RMEM(addr));
        }
        if (!BitCheck(d->reglist, SP)) {
            EMU(WREG(Rn) = RREG(Rn) + 4 * regcount); /* update SP */
        } else {
            emu_abort("unknown Rn %d %x", d->Rn, RREG(Rn));
        }

        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_bits(const darm_t * d) {
    switch(d->instr) {
    case I_BFI: {
        uint32_t lsb = d->lsb;
        uint32_t msb = lsb + d->width - 1;
        if (msb >= lsb) {
            /* R[d]<msb:lsb> = R[n]<(msb-lsb):0>; */
            /* 1. clear out        R[d]<msb:lsb>  = 0 */
            uint32_t val = RREG(Rd);
            val &= ~((1<<(msb + 1)) - (1<<lsb));
            emu_log_debug("Rd clear out   : %x\n", val);
            /* 2. extract Rn bits  bits = R[n]<(msb-lsb):0> */
            uint32_t bits = RREG(Rn);
            bits &= ((1<<(d->width)) - 1); /* width = msb - lsb + 1 */
            emu_log_debug("Rn extract bits: %x\n", bits);
            /* 3. set Rd bits      R[d]<msb:lsb> |= bits */
            val |= bits << lsb;
            emu_log_debug("Rd set bits    : %x\n", val);
            WREG(Rd) = val;
        }
        break;
    }
    case I_CLZ: {
        WREG(Rd) = LeadingZerosCount(RREG(Rm));
        WTREG1(Rd, Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_mul(const darm_t * d) {
    switch(d->instr) {
    case I_MUL: {
        /* TODO: move MUL to emu_dataop() and use OP macro instead */
        EMU(WREG(Rd) = RREG(Rn) * RREG(Rm));
        WTREG2(Rd, Rn, Rm);
        break;
    }
    case I_MLA: {
        EMU(WREG(Rd) = RREG(Rn) * RREG(Rm) + RREG(Ra));
        WTREG2(Rd, Rn, Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

void emu_type_uncond(const darm_t * d) {
    switch(d->instr) {
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
    case I_PLD:
    case I_PLI: {
        emu_log_debug("treating as NOP\n");
        break;
    }
        SWITCH_COMMON;
    }
}

inline uint32_t emu_dataop(const darm_t *d, const uint32_t a, const uint32_t b) {
    switch(d->instr) {
    case I_CMN :
    case I_ADD : return  a + b;
    case I_ADC : return  a + b  +  CPSR_C;
    case I_CMP :
    case I_SUB : return  a - b;
    case I_SBC : return (a - b) - !CPSR_C;
    case I_RSC : return (b - a) - !CPSR_C;
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
    emu.handled_instr++;
    emu_log_debug("handled instructions: %d\n", emu.handled_instr);
    dbg_dump_ucontext(&emu.current);
    emu_log_debug("\n");
    emu_log_debug("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
#ifndef PROFILE
    usleep(10 * 1000);          /* delay to allow printf flush to logcat */
#endif
    if (emu_regs_tainted() == 0) {
        emu_protect_mem();
        emu_stop();             /* will not return */
        emu_log_debug("taint: no tainted regs remaining, enable protection and leave emu\n");
    }
}

static inline void emu_set_taint_reg(uint32_t reg, uint32_t tag) {
    if (emu.taintreg[reg] != TAINT_CLEAR && tag == TAINT_CLEAR) {
        emu_log_debug("taint: un-tainting r%d\n", reg);
    } else if (emu.taintreg[reg] == TAINT_CLEAR && tag != TAINT_CLEAR) {
        emu_log_debug("taint: tainting r%d tag: %x", reg, tag);
    }
    emu.taintreg[reg] = tag;
}

static inline uint32_t emu_get_taint_reg(uint32_t reg) {
    return emu.taintreg[reg];
}

void emu_singlestep(uint32_t pc) {
#ifndef PROFILE
    emu_map_lookup(pc);
#endif

    // 1. decode instr
    // emu_disasm_ref(pc, (emu_thumb_mode() ? 16 : 32)); /* rasm2 with libopcodes backend */
    /* static const darm_t *d; */
    const darm_t *d;
    d = emu_disasm(pc); /* darm */
    /* check for invalid disassembly */
    /* best we can do is stop emu and resume execution at the instruction before the issue */
    if (!d) {
        emu_abort("invalid disassembly"); /* emu_stop() will get called after */
    }
#ifndef PROFILE
    darm_dump(d);           /* dump internal darm_t state */
#endif

    if (!emu_eval_cond(d->cond)) {
        emu_log_debug("skipping instruction: condition NOT passed\n");
        goto next;
    }

    // 2. emu instr by type
    switch(d->instr_type) {
    case T_ARM_ARITH_SHIFT:
    case T_THUMB_MOD_SP_REG: {
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
    case T_ARM_DST_SRC:
    case T_THUMB_MOV4: {
        emu_type_dst_src(d);
        break;
    }
    case T_ARM_STACK0:
    case T_ARM_STACK1:
    case T_ARM_STACK2:
    case T_ARM_LDSTREGS:
    case T_THUMB_RW_MEMO:
    case T_THUMB_RW_MEMI:
    case T_THUMB_STACK:
    case T_THUMB_LDR_PC: {
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
    case T_ARM_MVCR: {
        emu_type_mvcr(d);
        break;
    }
    case T_ARM_BITS:
    case T_ARM_BITREV: {
        emu_type_bits(d);
        break;
    }
    case T_ARM_MUL: {
        emu_type_mul(d);
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
    emu_log_info("starting emulation ...\n\n");

    /* disabled taintinfo_t usage and instead using explicit emu_set_taint APIs before entering emu */

    emu.enabled = 1;

    emu.time_start = time_ms();
    while(1) {                  /* infinite loop */
        emu_singlestep(CPU(pc));
    }
}

/* note: ucontext/setcontext support normally missing in Bionic */
/* unless ported to Bionic, hack it by returning 0 */
/* int setcontext (const ucontext_t *ucp) { return 0; } */

void emu_stop() {
    CPU(pc) |= emu_thumb_mode() ? 1 : 0; /* LSB set for Thumb */

    emu.time_end = time_ms();
    double delta = emu.time_end - emu.time_start;

    printf("resuming exec pc old: %0lx new: %0lx time total (ms): %f handled instr: %d time/instr (ns): %f\n",
           emu.original.uc_mcontext.arm_pc,
           emu.current.uc_mcontext.arm_pc,
           delta,
           emu.handled_instr,
           (delta * 1e6) / emu.handled_instr);

    emu.enabled = 0;
    if (emu_regs_tainted()) {
        emu_log_warn("WARNING: stopping emu with tainted regs!\n");
    }
    dbg_dump_ucontext(&emu.current);
    emu_log_debug("### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ###\n");
    pthread_mutex_unlock(&emu.lock);
    setcontext((const ucontext_t *)&emu.current); /* never returns */
}

uint8_t emu_stop_trigger() {
    static const darm_instr_t trigger = I_BKPT;

    if (darm->instr == trigger) {
        emu_log_debug("\n");
        emu_log_debug("special op %s being skipped\n", darm_mnemonic_name(trigger));
        CPU(pc) += 4;
        return 1;
    }
    return 0;
}

/* Setup emulation handler. */
void emu_register_handler() {
    if (emu.initialized == 1) return;

    emu.handled_instr = 0;
    pthread_mutex_init(&emu.lock, NULL);

    /* init darm */
    emu_log_debug("initializing darm disassembler ...\n");
    darm = malloc(sizeof(darm_t));

    /* process maps */
    emu_map_parse();

#ifndef NO_TAINT
    /* taint tag storage */
    mmap_init();
    emu_clear_taintpages();
#endif

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
        emu_abort("ss.ss_sp == NULL");
    }
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
        emu_abort("sigaltstack");
    }

    /* 2. setup signal handler */
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = emu_handler;
    /* sigaction (SIGSEGV, &sa, NULL); */
    /* FIX: do not register SIGPROF, used for profiling */
    // if (sigaction (SIGPROF, &sa, NULL) == -1) {
    //    emu_abort("error: sigaction SIGPROF");
    // }
    if (sigaction (SIGTRAP, &sa, NULL) == -1) {
        emu_abort("error: sigaction SIGTRAP");
    }

    /* 3. setup mprotect handler */
    mprotectInit();

    emu.initialized = 1;
}

const darm_t* emu_disasm(uint32_t pc) {
    return emu_disasm_internal(darm, pc); /* darm is a global variable */
}

const darm_t* emu_disasm_internal(darm_t *d, uint32_t pc) {
    uint32_t ins = *(const uint32_t *)pc;

    uint16_t w     = ins & 0xffff;
    uint16_t w2    = ins >> 16;
    uint32_t addr  = pc | emu_thumb_mode(); /* LSB set for Thumb / Thumb2 */
    uint8_t  bytes = darm_disasm(d, w, w2, addr);
    /* Returns 0 on failure, 1 for Thumb, 2 for Thumb2, and 2 for ARMv7. */
    emu_log_debug("emu_disasm : w: %x w2: %x addr: %x T: %d\n", w, w2, addr, emu_thumb_mode());
    if (bytes) {
#ifndef PROFILE
        darm_str_t str;
        darm_str2(d, &str, 1); /* lowercase str */
        emu_log_debug("darm : %x %x %s\n", pc, d->w, str.total);
#endif
        emu_log_debug("bytes: %d\n", bytes);
    } else {
        emu_log_error("darm : %x %x %x <invalid instruction>\n", pc, w, w2);
        return NULL;
    }
    return d;
}

static inline uint8_t emu_thumb_mode() {
    return CPSR_T;              /* 0: ARM, 1: Thumb */
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
    mcontext_t *r = &uc->uc_mcontext;
    emu_log_debug("ucontext dump:\n");
    emu_log_debug("fault addr %8x\n",
           (uint32_t)r->fault_address);
    emu_log_debug("r0: %8x  r1: %8x  r2: %8x  r3: %8x\n",
           (uint32_t)r->arm_r0, (uint32_t)r->arm_r1, (uint32_t)r->arm_r2,  (uint32_t)r->arm_r3);
    emu_log_debug("r4: %8x  r5: %8x  r6: %8x  r7: %8x\n",
           (uint32_t)r->arm_r4, (uint32_t)r->arm_r5, (uint32_t)r->arm_r6,  (uint32_t)r->arm_r7);
    emu_log_debug("r8: %8x  r9: %8x  sl: %8x  fp: %8x\n",
           (uint32_t)r->arm_r8, (uint32_t)r->arm_r9, (uint32_t)r->arm_r10, (uint32_t)r->arm_fp);
    emu_log_debug("ip: %8x  sp: %8x  lr: %8x  pc: %8x  cpsr: %8x\n",
           (uint32_t)r->arm_ip, (uint32_t)r->arm_sp, (uint32_t)r->arm_lr,  (uint32_t)r->arm_pc, (uint32_t)r->arm_cpsr);
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
            emu_log_debug("dbg: %-4s: %8x -> %8x\n",
                   sigcontext_names[i],
                   previous, current);
        }
    }
    emu.previous = emu.current;
}

static void emu_dump_cpsr() {
    emu_log_debug("cpsr [%c%c%c%c %c %c]\n",
           CPSR_N ? 'N' : 'n',
           CPSR_Z ? 'Z' : 'z',
           CPSR_C ? 'C' : 'c',
           CPSR_V ? 'V' : 'v',
           CPSR_I ? 'I' : 'i',
           CPSR_T ? 'T' : 't'
           );
}

static void emu_map_dump(map_t *m) {
    if (m != NULL) {
        emu_log_debug("%x-%x %c%c%c%c %x %x:%x %u %s [%u pages]\n",
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
            emu_log_error("unexpected line: %s\n", buf);
            continue;
        }
        emu.maps[emu.nr_maps] = m;
        if (++emu.nr_maps >= MAX_MAPS) {
            emu_abort("too many maps\n");
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
            emu_log_debug("lib map %8x -> %8x\n", addr, addr - m->vm_start);
            emu_map_dump(m);
            return m;
        }
    }
    emu_log_debug("unable to locate addr: %x\n", addr);
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
        emu_log_error("error: sysconf %d", pageSize);

    emu_log_debug("Page Size = %d bytes\n", pageSize);

    return pageSize;
}

static inline uint32_t
getAlignedPage(uint32_t addr) {
    return addr & ~ (getPageSize() - 1);
}

static void
mprotectHandler(int sig, siginfo_t *si, void *ucontext) {
    pthread_mutex_lock(&emu.lock);

    uint32_t pc = (*(ucontext_t *)ucontext).uc_mcontext.arm_pc;
    uint32_t addr_fault = (*(ucontext_t *)ucontext).uc_mcontext.fault_address;

    emu_log_debug("\n### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ###\n");

    emu_log_debug("SIG %d with TRAP code: %d pc: %x addr: %x\n",
               sig,
               si->si_code,
               pc,
               addr_fault);

    assert((uint32_t)si->si_addr == addr_fault);

    switch(si->si_code) {
    case SEGV_MAPERR:
        emu_log_debug("Address not mapped to object\n");
        break;
    case SEGV_ACCERR:
        emu_log_debug("Invalid permissions for mapped object\n");
        break;
    default:
        emu_log_debug("Unknown SI Code\n");
        break;
    }

    emu_map_lookup(pc);
    emu_map_lookup(addr_fault);

    if (emu.enabled == 1) {
        dbg_dump_ucontext((ucontext_t *)ucontext);
        emu_abort("massive fuckup, trapping while in emu!\n");
    }

    emu_init((ucontext_t *) ucontext);

    emu_log_debug("fault addr: %x fixing permissions for page: %x\n", addr_fault, getAlignedPage(addr_fault));

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

        emu_log_debug("un-protecting mem before singlestep...\n");
        emu_unprotect_mem();

        emu.enabled = 1;

        emu_log_debug("singlestep instruction at pc: %x\n", pc);
        emu_singlestep(pc);

        emu_log_debug("protecting mem after singlestep...\n");
        emu_protect_mem();

        emu_stop();             /* this should not be reached */
    }
}

static void
mprotectInit() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK; /* doesn't clobber original stack */
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = mprotectHandler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        emu_abort("error: sigaction SIGSEGV");
    }
}

/* TODO: add length and determine if page boundary crossed */
static void
mprotectPage(uint32_t addr, uint32_t flags) {
    uint32_t addr_aligned = getAlignedPage(addr); /* align at pageSize */
    emu_log_debug("update protection on page: %x given addr: %x\n", addr_aligned, addr);
    emu_map_lookup(addr);

    if (mprotect((void *)addr_aligned, getPageSize(),
                 flags) == -1) {
        emu_abort("error: mprotect errno %d: %s\n", errno, strerror(errno));
    }
    emu_log_debug("page protection updated\n");
}

static void
mmap_init() {
    uint32_t start, end, bytes;

    /* lib taintmap */

    start = emu.maps[0].vm_start;
    end   = emu.maps[emu.nr_maps - 3].vm_end;
    bytes = end - start;

    emu_log_debug("mmap lib   range: %x - %x length: %x\n", start, end, bytes);

    emu.taintmaps[TAINTMAP_LIB].data     = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    emu.taintmaps[TAINTMAP_LIB].start    = start;
    emu.taintmaps[TAINTMAP_LIB].end      = end;
    emu.taintmaps[TAINTMAP_LIB].bytes    = bytes;

    emu_log_debug("mmap lib   returned: %p\n", emu.taintmaps[TAINTMAP_LIB].data);
    if(emu.taintmaps[TAINTMAP_LIB].data == MAP_FAILED) {
        emu_abort("mmap lib failed");
    }

    /* stack taintmap */

    start = emu.maps[emu.nr_maps - 2].vm_start;
    end   = emu.maps[emu.nr_maps - 2].vm_end;
    bytes = end - start;

    emu_log_debug("mmap stack range: %x - %x length: %x\n", start, end, bytes);

    emu.taintmaps[TAINTMAP_STACK].data   = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    emu.taintmaps[TAINTMAP_STACK].start  = start;
    emu.taintmaps[TAINTMAP_STACK].end    = end;
    emu.taintmaps[TAINTMAP_STACK].bytes  = bytes;

    emu_log_debug("mmap stack returned: %p\n", emu.taintmaps[TAINTMAP_STACK].data);
    if (emu.taintmaps[TAINTMAP_STACK].data  == MAP_FAILED) {
        emu_abort("mmap stack failed");
    }

    emu_log_debug("taintmaps initialized\n");
}

static taintmap_t *
emu_get_taintmap(uint32_t addr) {
    addr = Align(addr, 4);      /* word align */

    uint32_t stack_start = emu.maps[emu.nr_maps - 2].vm_start;
    uint8_t  idx         = (addr > stack_start) ? TAINTMAP_STACK : TAINTMAP_LIB;
    return &emu.taintmaps[idx];
}

static uint32_t
emu_dump_taintmaps() {
    uint32_t idx, offset;
    taintmap_t *tm;
    for (idx = TAINTMAP_LIB; idx < MAX_TAINTMAPS; idx++) {
        tm = &emu.taintmaps[idx];
        if (tm->data == NULL) {
            /* FIXME: this should only occur for the 3rd (heap, idx 2) unused map */
            emu_log_debug("unallocated data for taintmap %d", idx);
            continue;
        }
        for (offset = 0; offset < tm->bytes >> 2; offset++) {
            if (tm->data[offset] != TAINT_CLEAR) {
                emu_log_debug("taint: %s offset: %x addr: %x tag: %x\n",
                       (idx == TAINTMAP_LIB) ? "lib" : "stack",
                       offset,
                       tm->start + offset * sizeof(uint32_t), tm->data[offset]
                       );
            }
        }
    }
    return 0;
}

static uint32_t
emu_get_taint_mem(uint32_t addr) {
    addr = Align(addr, 4);      /* word align */
    taintmap_t *taintmap = emu_get_taintmap(addr);

    if (taintmap->data == NULL || taintmap->start == 0) {
        emu_abort("uninitialized taintmap");
    }

    uint32_t    offset   = (addr - taintmap->start) >> 2;
    if (offset < taintmap->start && offset > taintmap->end) {
        emu_abort("out of bounds offset");
    }
    uint32_t    tag      = taintmap->data[offset]; /* word (32-bit) based tag storage */
    // emu_log_debug("addr: %x offset: %x tag: %x", addr, offset, tag);
    return tag;
}

void emu_set_taint_mem(uint32_t addr, uint32_t tag) {
    if (!addr || !tag) {
        emu_abort("invalid taint addr: %x tag: %x", addr, tag);
    }

    addr = Align(addr, 4);      /* word align */
    taintmap_t *taintmap   = emu_get_taintmap(addr);
    uint32_t    offset     = (addr - taintmap->start) >> 2;

    // emu_log_debug("addr: %x offset: %x tag: %x", addr, offset, tag);

    if (taintmap->data == NULL || taintmap->start == 0) {
        emu_abort("uninitialized taintmap");
    }
    if (offset < taintmap->start && offset > taintmap->end) {
        emu_abort("out of bounds offset");
    }

    /* incrementally iupdate tainted page list */
    if (taintmap->data[offset] != TAINT_CLEAR && tag == TAINT_CLEAR) {
        emu_log_debug("taint: un-tainting mem: %x\n", addr);
        emu_unmark_page(addr);
    } else if (taintmap->data[offset] == TAINT_CLEAR && tag != TAINT_CLEAR) {
        emu_log_debug("taint: tainting mem: %x tag: %x\n", addr, tag);
        emu_mark_page(addr);
    }
    taintmap->data[offset] = tag;  /* word (32-bit) based tag storage */
}

void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length) {
    emu_abort("unimplemented");
}

static int emu_mark_page(uint32_t addr) {
    uint32_t page = getAlignedPage(addr);
    uint32_t idx;
    uint8_t found = 0;
    uint8_t added = 0;

    /* 1. look if page has been marked previously marked */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        if (emu.taintpages[idx] == page) {
            found = 1;
            return found;
        }
    }

    /* 2. if page not found, add it */
    if (!found) {
        for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
            if (emu.taintpages[idx] == 0) {
                emu.taintpages[idx] = page;
                added = 1;
                break;
            }
        }
        if (!added) {
            emu_abort("maximum number of protected pages (%d) reached!", MAX_TAINTPAGES);
        }
    }
    return added;
}

static int emu_unmark_page(uint32_t addr) {
    uint32_t page = getAlignedPage(addr);
    uint32_t idx;
    uint8_t found = 0;

    /* 1. look if page has been marked previously marked */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        if (emu.taintpages[idx] == page) {
            found = 1;
            emu.taintpages[idx] = 0;
            break;
        }
    }
    return found;
}

static void
emu_clear_taintpages() {
    uint32_t idx;
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        emu.taintpages[idx] = 0;
    }
}

static void
emu_protect_mem() {
    uint32_t idx;
    /* protect all pages in unique list */
    uint32_t flags = PROT_NONE;
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        uint32_t page = emu.taintpages[idx];
        if (page != 0) {
            mprotectPage(page, flags);
        }
    }
}

static void
emu_unprotect_mem() {
    uint32_t idx;
    uint32_t flags = PROT_READ | PROT_WRITE;
    /* un-protect all pages in unique page list */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        uint32_t page = emu.taintpages[idx];
        if (page != 0) {
            mprotectPage(page, flags);
        }
    }
}

bool emu_enabled() {
    return emu.enabled;
}

static inline uint32_t
instr_mask(darm_instr_t instr) {
    switch(instr) {
    case I_LDRB:
    case I_STRB: { return 0xff; }
    case I_LDRH:
    case I_STRH: { return 0xffff; }
    default:     { return 0xffffffff; }
    }
}

static inline double time_ms(void) {
    struct timespec res;
    clock_gettime(CLOCK_MONOTONIC, &res);
    double result = 1000.0 * res.tv_sec + (double) res.tv_nsec / 1e6;
    // printf("sec: %ld nsec: %ld\n", res.tv_sec, res.tv_nsec);
    return result;
}
